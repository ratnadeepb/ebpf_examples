static const char *__doc__
    = "XDP loader\n"
      " - Specify BPF-object --filename to load \n"
      " - and select BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"

static const char *default_filename = "xdp_kern.o";
static const char *default_progsec = "xdp_pass_func";

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

        { { "offload-mode", no_argument, NULL, 3 },
          "Hardware offload XDP program to NIC" },

        { { "force", no_argument, NULL, 'F' },
          "Force install, replacing existing program on interface" },

        { { "unload", no_argument, NULL, 'U' },
          "Unload XDP program instead of loading" },

        { { "quiet", no_argument, NULL, 'q' }, "Quiet mode (no output)" },

        { { "filename", required_argument, NULL, 1 },
          "Load program from <file>",
          "<file>" },

        { { "progsec", required_argument, NULL, 2 },
          "Load program in <section> of the ELF file",
          "<section>" },

        { { 0, 0, NULL, 0 }, NULL, false } };

void
xdp_unpin (struct bpf_link *link)
{
  int err;
  if ((err = bpf_link__unpin (link)) < 0)
    {
      perror ("Err: Unlinking failed");
    }
}

struct bpf_program *
xdp_obj_prog (struct bpf_object *bpf_obj, const char *fname)
{
  /* Find a matching BPF prog section name */
  struct bpf_program *bpf_prog;

  bpf_prog = bpf_object__find_program_by_name (bpf_obj, fname);
  if (!bpf_prog)
    {
      fprintf (stderr, "ERR: finding progsec: %s\n", fname);
      exit (EXIT_FAIL_BPF);
    }
  return bpf_prog;
}

int
xdp_prog_fd (struct bpf_program *bpf_prog)
{
  int prog_fd = -1;
  prog_fd = bpf_program__fd (bpf_prog);
  if (prog_fd <= 0)
    {
      fprintf (stderr, "ERR: bpf_program__fd failed\n");
      exit (EXIT_FAIL_BPF);
    }
  return prog_fd;
}

int
xdp_obj_2_fd (struct bpf_object *bpf_obj, const char *fname)
{
  return xdp_prog_fd (xdp_obj_prog (bpf_obj, fname));
}

struct bpf_object *
__load_bpf_object_file (const char *filename, int ifindex)
{
  struct bpf_object *obj;

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
      bpf_object__close (obj);
    }

  return obj;
}

struct bpf_link *
xdp_link_attach (int ifindex, struct bpf_object *bpf_obj, const char *fname)
{
  /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
   * is our select file-descriptor handle. Next step is attaching this FD
   * to a kernel hook point, in this case XDP net_device link-level hook.
   */
  struct bpf_link *link;
  //   struct bpf_program *prog;

  //   prog = bpf_object__find_program_by_name (bpf_obj, fname);

  link = xdp_link_attach (ifindex, bpf_obj, fname);
  //   link = bpf_program__attach_xdp (prog, ifindex);
  if (!link)
    {
      perror ("ERR: xdp_link_attach failed");
      bpf_link__destroy (link);
      fprintf (stderr, "ERR: xdp_link_attach failed\n");
      exit (EXIT_FAIL_BPF);
    }

  return link;
}

struct bpf_object *
__load_bpf_and_xdp_attach (struct config *cfg)
{
  int offload_ifindex = 0;
  struct bpf_program *bpf_prog;
  struct bpf_object *bpf_obj;
  int err;

  if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
    offload_ifindex = cfg->ifindex;

  /* Load the BPF-ELF object file and get back libbpf bpf_object */
  bpf_obj = __load_bpf_object_file (cfg->filename, offload_ifindex);
  if (!bpf_obj)
    {
      fprintf (stderr, "ERR: loading file: %s\n", cfg->filename);
      exit (EXIT_FAIL_BPF);
    }

  bpf_prog = xdp_obj_prog (bpf_obj, cfg->progsec);

  //   /* Set XDP flags. */
  //   err = bpf_program__set_flags (bpf_prog, cfg->xdp_flags);
  //   if (err)
  //     {
  //       perror ("Set flags error");
  //       fprintf (stderr, "ERR: bpf_program__set_flags failed\n");
  //       exit (EXIT_FAIL_BPF);
  //     }

  return bpf_obj;
}

int
xdp_link_detach (int ifindex, __u32 xdp_flags, __u32 expected_prog_id,
                 struct bpf_link *link)
{
  __u32 curr_prog_id;
  int err;

  err = bpf_xdp_query_id (ifindex, xdp_flags, &curr_prog_id);
  if (err)
    {
      fprintf (stderr, "ERR: get link xdp id failed (err=%d): %s\n", -err,
               strerror (-err));
      return EXIT_FAIL_XDP;
    }

  if (!curr_prog_id)
    {
      if (verbose)
        printf ("INFO: %s() no curr XDP prog on ifindex:%d\n", __func__,
                ifindex);
      return EXIT_OK;
    }

  if (expected_prog_id && curr_prog_id != expected_prog_id)
    {
      fprintf (stderr,
               "ERR: %s() "
               "expected prog ID(%d) no match(%d), not removing\n",
               __func__, expected_prog_id, curr_prog_id);
      return EXIT_FAIL;
    }

  if ((err = bpf_link__detach (link)) < 0)
    {
      fprintf (stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
               __func__, err, strerror (-err));
      return EXIT_FAIL_XDP;
    }

  bpf_link__destroy (link);

  if (verbose)
    printf ("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n", __func__,
            curr_prog_id, ifindex);

  return EXIT_OK;
}

static void
list_avail_progs (struct bpf_object *obj)
{
  struct bpf_program *pos;
  printf ("BPF object (%s) listing avail --progsec names\n",
          bpf_object__name (obj));
  bpf_object__for_each_program (pos, obj)
  {
    // libbpf_bpf_prog_type_str()
    if (bpf_program__type (pos) == BPF_PROG_TYPE_XDP)
      printf (" %s\n", bpf_program__name (pos));
  }
}

int
main (int argc, char **argv)
{
  struct bpf_object *bpf_obj;
  struct bpf_link *bpf_link;

  struct config cfg = {
    .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
    .ifindex = -1,
    .do_unload = false,
  };

  /* Set default BPF-ELF object file and BPF program name */
  strncpy (cfg.filename, default_filename, sizeof (cfg.filename));
  strncpy (cfg.progsec, default_progsec, sizeof (cfg.progsec));

  /* Cmdline options can change these */
  parse_cmdline_args (argc, argv, long_options, &cfg, __doc__);

  /* Required option */
  if (cfg.ifindex == -1)
    {
      fprintf (stderr, "ERR: required option --dev missing\n");
      usage (argv[0], __doc__, long_options, (argc == 1));
      return EXIT_FAIL_OPTION;
    }

  if (cfg.do_unload)
    {
      printf ("Unloading\n");
      bpf_xdp_detach (cfg.ifindex, cfg.xdp_flags, NULL);
    }

  bpf_obj = __load_bpf_and_xdp_attach (&cfg);
  if (!bpf_obj)
    return EXIT_FAIL_BPF;

  bpf_link = xdp_link_attach (cfg.ifindex, bpf_obj, cfg.progsec);
  bpf_link__pin (bpf_link, "/sys/fs/bpf/");

  if (cfg.do_unload)
    xdp_link_detach (cfg.ifindex, cfg.xdp_flags, 0, bpf_link);

  if (verbose)
    list_avail_progs (bpf_obj);

  if (verbose)
    {
      printf ("Success: Loaded BPF-object(%s) and used section(%s)\n",
              cfg.filename, cfg.progsec);
      printf (" - XDP prog attached on device:%s(ifindex:%d)\n", cfg.ifname,
              cfg.ifindex);
    }

  /* Other BPF section programs will get freed on exit */
  return EXIT_OK;
}