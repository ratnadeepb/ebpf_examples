#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC ("xdp")
int
xdp_prog_simple (struct xdp_md *ctx)
{
  return XDP_PASS;
}

char _licenes[] SEC ("license") = "GPL";