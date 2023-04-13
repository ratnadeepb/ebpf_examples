#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h"

/* Maintain states per XDP action */
struct
{
  __uint (type, BPF_MAP_TYPE_ARRAY);
  __uint (max_entries, XDP_ACTION_MAX);
  __type (key, __u32);
  __type (value, struct datarec);
} xdp_stats_map SEC (".maps");

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic
 * add instruction (that is BPF_STX | BPF_XADD | BPF_W for word size) */
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add (ptr, val))
#endif

SEC ("xdp")
int
xdp_stats1_func (struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct datarec *rec;
  __u32 key = XDP_PASS; /* XDP_PASS = 2 */

  /* Lookup in the kernel BPF side return pointer to actual data record */
  rec = bpf_map_lookup_elem (&xdp_stats_map, &key);
  /* BPF kernel-side verifier will reject program if the NULL pointer
   * check isn't performed here. Even-though this is a static array where
   * we know key lookup XDP_PASS always will succeed.
   */
  if (!rec)
    return XDP_ABORTED;

  /* Multiple CPUs can access data record. Thus, the accounting needs to
   * use an atomic operation.
   */
  lock_xadd (&rec->rx_packets, 1);
  lock_xadd (&rec->rx_bytes, (data_end - data));

  return XDP_PASS;
}

char _license[] SEC ("license") = "GPL";