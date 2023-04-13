#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC ("xdp")
int
xdp_pass_func (struct xdp_md *ctx)
{
  return XDP_PASS;
}

SEC ("xdp")
int
xdp_drop_func (struct xdp_md *ctx)
{
  return XDP_DROP;
}

SEC ("xdp")
int
xdp_abort_func (struct xdp_md *ctx)
{
  return XDP_ABORTED;
}

char __license[] SEC ("license") = "GPL";