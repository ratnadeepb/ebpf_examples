# Using EBPF

## Setup

[Reference](https://arthurchiao.art/blog/firewalling-with-bpf-xdp/)</br>
[Dropbox](https://paper.dropbox.com/doc/BPF-Setup--BUI003bDeTGlJlnYEQpGj9ipAg-haT7cbcjpOdR8mKn9FKTr)

```bash
sudo apt install libelf-dev linux-libc-dev libc6-dev-i386 build-essential build-essential # gcc-multilib linux-tools-$(uname -r) linux-headers-$(uname -r) linux-headers-generic linux-tools-common linux-tools-generic
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make
sudo make install
sudo apt install llvm # llc
sudo apt install linux-tools-common # bpftool
```

## Compiling

```bash
clang -O3 -Wall -target bpf -c code. -o code.o
```

## nsenter

### Function

```bash
function nsenter-ctn () {
    CTN=$1 # Container ID or name
    PID=$(sudo docker inspect --format "{{.State.Pid}}" $CTN)
    shift 1 # Remove the first arguement, shift remaining ones to the left
    sudo nsenter -t $PID $@
}
```

### Running It

```bash
nsenter-ctn ctn1 -n ip a
nsenter-ctn ctn2 -n ip a
nsenter-ctn ctn1 -n arping 172.17.0.3
nsenter-ctn ctn1 -n ping 172.17.0.3 -c 2
nsenter-ctn ctn1 -n curl 172.17.0.3:80
nsenter-ctn ctn2 -n tcpdump -nn -i eth0
nsenter-ctn ctn2 -n tc qdisc add dev eth0 clsact
nsenter-ctn ctn2 -n tc filter add dev eth0 ingress bpf da obj drop-arp.o sec ingress
nsenter-ctn ctn2 -n tc filter show dev eth0 ingress
nsenter-ctn ctn2 -n tcpdump -i eth0 arp
```

## Further Reading

- SO_REUSEPORT eBPF:
    - [Video](https://www.youtube.com/watch?v=CgB7JpSL5cs&t=8212s)
    - [PDF](https://linuxplumbersconf.org/event/11/contributions/946/attachments/783/1472/Socket_migration_for_SO_REUSEPORT.pdf)
- [Learning the Linux Kernel with tracing](https://www.youtube.com/watch?v=JRyrhsx-L5Y&t=710s)
- [Understanding and Troubleshooting the eBPF Datapath in Cilium](https://www.youtube.com/watch?v=Kmm8Hl57WDU&t=760s)
- [Cilium overlay datapath egress deep dive 1](https://www.youtube.com/watch?v=Ocy2pFhNFfE)
- [Calico Networking with eBPF](https://www.youtube.com/watch?v=KHMnC3kj3Js)
- [eBPF / XDP Based Firewall and Packet Filtering -- Facebook](https://www.youtube.com/watch?v=XpBzEq1MwI8)
- [Connection Tracking](https://arthurchiao.art/blog/conntrack-design-and-implementation/)
- [Life of a Packet in Cilium](https://arthurchiao.art/blog/cilium-life-of-a-packet-pod-to-service/)
- [Bottom Up EBPF](https://medium.com/@phylake/bottom-up-ebpf-d7ca9cbe8321)

