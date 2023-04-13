static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h>
#include <net/if.h>

#include "../common/common_params.h"

static const struct option_wrapper long_options[]
    = { { { "help", no_argument, NULL, 'h' }, "Show help", false },

        { { "dev", required_argument, NULL, 'd' },
          "Operate on device <ifname>",
          "<ifname>",
          true },

        { { "skb-mode", no_argument, NULL, 'S' },
          "Install XDP program in SKB (AKA generic) mode" },

        { { "native-mode", no_argument, NULL, 'N' },
          "Install XDP program in native mode" },

        { { "auto-mode", no_argument, NULL, 'A' },
          "Auto-detect SKB or native mode" },

        { { "force", no_argument, NULL, 'F' },
          "Force install, replacing existing program on interface" },

        { { "unload", no_argument, NULL, 'U' },
          "Unload XDP program instead of loading" },

        { { 0, 0, NULL, 0 }, NULL, false } };

int
load_bpf_object_file_simple (const char *filename)
{
  struct bpf_obj *obj;

  /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
   * loading this into the kernel via bpf-syscall
   */
  obj = bpf_object__open_file (filename, NULL);
  if (libbpf_get_error (obj))
    {
      fprintf (stderr, "ERROR: opening BPF object file failed\n");
      return 0;
    }
  /* load BPF program */
  if (bpf_object__load (obj))
    {
      fprintf (stderr, "ERROR: loading BPF object file failed\n");
      goto cleanup;
    }

  struct bpf_program *prog
      = bpf_object__find_program_by_name (obj, "xdp_prog_simple");

  struct bpf_link *link = bpf_program__attach (prog);

  for (;;)
    ;

cleanup:
  bpf_link__destroy (link);
  bpf_object__close (obj);

  return 0;
}

int
main (void)
{
  char filename[256] = "xdp_pass_kern.o";
  int prog_fd = load_bpf_object_file_simple (filename);
}