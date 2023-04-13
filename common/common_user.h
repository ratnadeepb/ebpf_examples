#ifndef __COMMON_USER_HEADERS__
#define __COMMON_USER_HEADERS__
#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

static unsigned int ifindex;
static const char *iface;
static struct xdp_kern *obj;
static int flags;

static bool verbose;

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

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

#define XDP_UNKNOWN XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

static const char *xdp_action_names[XDP_ACTION_MAX] = {
  [XDP_ABORTED] = "XDP_ABORTED",   [XDP_DROP] = "XDP_DROP",
  [XDP_PASS] = "XDP_PASS",         [XDP_TX] = "XDP_TX",
  [XDP_REDIRECT] = "XDP_REDIRECT", [XDP_UNKNOWN] = "XDP_UNKNOWN",
};

const char *
action2str (__u32 action)
{
  if (action < XDP_ACTION_MAX)
    return xdp_action_names[action];
  return NULL;
}

static inline unsigned int
bpf_num_possible_cpus (void)
{
  static const char *fcpu = "/sys/devices/system/cpu/possible";
  unsigned int start, end, possible_cpus = 0;
  char buff[128];
  FILE *fp;
  int n;

  fp = fopen (fcpu, "r");
  if (!fp)
    {
      printf ("Failed to open %s: '%s'!\n", fcpu, strerror (errno));
      exit (1);
    }

  while (fgets (buff, sizeof (buff), fp))
    {
      n = sscanf (buff, "%u-%u", &start, &end);
      if (n == 0)
        {
          printf ("Failed to retrieve # possible CPUs!\n");
          exit (1);
        }
      else if (n == 1)
        {
          end = start;
        }
      possible_cpus = start == 0 ? end + 1 : 0;
      break;
    }
  fclose (fp);

  return possible_cpus;
}

#endif // __COMMON_USER_HEADERS__