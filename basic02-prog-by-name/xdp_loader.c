#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "xdp.skel.h"

static unsigned int ifindex;
static const char *iface;
static struct xdp_kern *obj;
static int flags;

static int
libbpf_print (enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG)
    {
      return 0;
    }
  return vfprintf (stderr, format, args);
}

int
xdp_detach_prog ()
{
  /* Remove BPF from network interface */
  int fd = -1;
  int err = 0;
  err = bpf_xdp_attach (ifindex, fd, flags, NULL);
  if (err)
    {
      fprintf (stderr, "failed to detach BPF from iface %s (%d): %d\n", iface,
               ifindex, err);
    }
  return err;
}

void
cleanup_xdp (int sig)
{
  fprintf (stderr, "Received signal %d\n", sig);
  xdp_detach_prog ();
  xdp_kern__destroy (obj);
}

int
main (int argc, char **argv)
{
  int opt = 1;
  if (argc < 2)
    {
      fprintf (stderr, "usage: %s <iface>\n", argv[0]);
      return EXIT_FAILURE;
    }
  if (argc > 2)
    opt = atoi (argv[2]);

  iface = argv[1];
  ifindex = if_nametoindex (iface);
  if (!ifindex)
    {
      perror ("failed to resolve iface to ifindex");
      return EXIT_FAILURE;
    }

  struct rlimit rlim = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };
  if (setrlimit (RLIMIT_MEMLOCK, &rlim))
    {
      perror ("failed to increase RLIMIT_MEMLOCK");
      return EXIT_FAILURE;
    }

  libbpf_set_print (libbpf_print);

  int err;
  obj = xdp_kern__open_and_load ();
  if (!obj)
    {
      fprintf (stderr, "failed to open BPF object\n");
      return EXIT_FAILURE;
    }

  /*
   * Use "xdpgeneric" mode; less performance but supported by all drivers
   */
  flags = XDP_FLAGS_SKB_MODE;
  int fd;

  switch (opt)
    {
    case 1:
      fprintf (stdout, "Passing XDP\n");
      fd = bpf_program__fd (obj->progs.xdp_pass_func);
      break;
    case 2:
      fprintf (stdout, "Dropping XDP\n");
      fd = bpf_program__fd (obj->progs.xdp_drop_func);
      break;
    case 3:
      fprintf (stdout, "Aborting XDP\n");
      fd = bpf_program__fd (obj->progs.xdp_abort_func);
      break;

    default:
      fprintf (stderr, "Unrecognized option\n");
      goto cleanup;
      break;
    }

    if (fd < 0) {
      fprintf(stderr, "Failed to get program file descriptor\n");
      goto cleanup;
    }

  /* Attach BPF to network interface */
  err = bpf_xdp_attach (ifindex, fd, flags, NULL);
  if (err)
    {
      fprintf (stderr, "failed to attach BPF to iface %s (%d): %d\n", iface,
               ifindex, err);
      goto cleanup;
    }

  /* Remove BPF from network interface */
  signal (SIGINT, cleanup_xdp);
  signal (SIGTERM, cleanup_xdp);

cleanup:
  xdp_kern__destroy (obj);
  if (err)
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}