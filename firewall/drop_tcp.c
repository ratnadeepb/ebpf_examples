#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

__attribute__ ((section ("ingress"), used)) int
drop (struct __sk_buff *skb)
{
  const int l3_off = ETH_HLEN;                       // IP header offset
  const int l4_off = l3_off + sizeof (struct iphdr); // TCP header offset
  const int l7_off
      = l4_off + sizeof (struct tcphdr); // L7 (e.g. HTTP) header offset

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data_end < data + l7_off)
    return TC_ACT_OK; // Not our packet, handover to kernel

  struct ethhdr *eth = data;
  if (eth->h_proto != htons (ETH_P_IP))
    return TC_ACT_OK; // Not an IPv4 packet, handover to kernel

  struct iphdr *ip = (struct iphdr *)(data + l3_off);
  if (ip->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
  if (ntohs (tcp->dest) != 80)
    return TC_ACT_OK;

  return TC_ACT_SHOT;
}
