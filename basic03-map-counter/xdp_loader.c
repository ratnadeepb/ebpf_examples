#include <time.h>
#include <locale.h>
#include "../common/common_user.h"
#include "xdp.skel.h"
#include "common_kern_user.h"

const char *pin_basedir = "/sys/fs/bpf";
const char *map_name = "xdp_stats_map";

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Pinning maps under /sys/fs/bpf in subdir */
int
pin_maps_in_bpf_object (struct bpf_object *bpf_obj, const char *subdir)
{
  char map_filename[PATH_MAX];
  char pin_dir[PATH_MAX];
  int err, len;

  len = snprintf (pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
  if (len < 0)
    {
      fprintf (stderr, "ERR: creating pin dirname\n");
      return EXIT_FAIL_OPTION;
    }

  len = snprintf (map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, subdir,
                  map_name);
  if (len < 0)
    {
      fprintf (stderr, "ERR: creating map_name\n");
      return EXIT_FAIL_OPTION;
    }

  /* Existing/previous XDP prog might not have cleaned up */
  err = bpf_object__unpin_maps(bpf_obj, map_filename);
  // bpf_object__unpin_programs()
  // bpf_obj_get()
}

    void cleanup_xdp (int sig)
{
  fprintf (stderr, "Received signal %d\n", sig);
  xdp_detach_prog ();
  xdp_kern__destroy (obj);
}

// int
// find_map_fd (struct bpf_object *bpf_object, const char *mapname)
// {
//   struct bpf_map *map;
//   int map_fd = -1;

//   /* BPF object to BPF map */
//   map = bpf_object__find_map_by_name (bpf_object, mapname);
//   if (!map)
//     {
//       fprintf (stderr, "ERR: cannot find map by name: %s\n", mapname);
//       goto out;
//     }
//   map_fd = bpf_map__fd (map);
// out:
//   return map_fd;
// }

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64
gettime (void)
{
  struct timespec t;
  int res;

  res = clock_gettime (CLOCK_MONOTONIC, &t);
  if (res < 0)
    {
      fprintf (stderr, "Error with gettimeofday! (%i)\n", res);
      exit (EXIT_FAILURE);
    }
  return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record
{
  __u64 timestamp;
  struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record
{
  struct record stats[1]; /* Assignment#2: Hint */
};

static double
calc_period (struct record *r, struct record *p)
{
  double period_ = 0;
  __u64 period = 0;

  period = r->timestamp - p->timestamp;
  if (period > 0)
    period_ = ((double)period / NANOSEC_PER_SEC);

  return period_;
}

static void
stats_print (struct stats_record *stats_rec, struct stats_record *stats_prev)
{
  struct record *rec, *prev;
  double period;
  __u64 packets;
  double pps; /* packets per sec */

  /* Assignment#2: Print other XDP actions stats  */
  {
    char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
                " %'11lld Kbytes (%'6.0f Mbits/s)"
                " period:%f\n";
    const char *action = action2str (XDP_PASS);
    rec = &stats_rec->stats[0];
    prev = &stats_prev->stats[0];

    period = calc_period (rec, prev);
    if (period == 0)
      return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period;

    printf (fmt, action, rec->total.rx_packets, rec->total.rx_bytes, pps, period);
  }
}

/* BPF_MAP_TYPE_ARRAY */
void
map_get_value_array (int fd, __u32 key, struct datarec *val)
{
  if ((bpf_map_lookup_elem (fd, &key, val)) != 0)
    {
      fprintf (stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    }
}

/* BPF_MAP_TYPE_PER_CPU_ARRAY */
void
map_get_value_per_cpu_array (int fd, __u32 key, struct datarec *val)
{
  /* Per CPU maps, userspace gets a value per possible CPU */
  unsigned int nr_cpus = bpf_num_possible_cpus ();
  struct datarec vals[nr_cpus];
  fprintf (stderr, "ERR: %s() not impl. see assignment#3", __func__);
}

static bool
map_collect (int fd, __u32 map_type, __u32 key, struct record *rec)
{
  struct datarec val;

  /* Get time as close as possible to reading map contents */
  rec->timestamp = gettime ();

  switch (map_type)
    {
    case BPF_MAP_TYPE_ARRAY:
      map_get_value_array (fd, key, &val);
      break;

    case BPF_MAP_TYPE_PERCPU_ARRAY:
      map_get_value_per_cpu_array (fd, key, &val);

    default:
      fprintf (stderr, "ERR: Unknown map_type(%u) cannot handle\n", map_type);
      break;
    }

  rec->total.rx_packets = val.rx_packets;
  rec->total.rx_bytes = val.rx_bytes;
  return true;
}

static void
stats_collect (int map_fd, __u32 map_type, struct stats_record *stats_rec)
{
  /* Assignment#2: Collect other XDP actions stats  */
  for (int i = 0; i < XDP_UNKNOWN; i++) {
    fprintf(stdout, "Action: %s\n", xdp_action_names[i]);
  }
  __u32 key = XDP_PASS;

  map_collect (map_fd, map_type, key, &stats_rec->stats[0]);
}

static void
stats_poll (int map_fd, __u32 map_type, int interval)
{
  struct stats_record prev, record = { 0 };

  /* Trick to pretty printf with thousands of separators use %' */
  setlocale (LC_NUMERIC, "en_US");

  /* Print stats "header" */
  if (verbose)
    {
      printf ("\n");
      printf ("%-12s\n", "XDP-action");
    }

  /* Get initial reading quickly */
  stats_collect (map_fd, map_type, &record);
  usleep (1000000 / 4);

  while (1)
    {
      prev = record; /* struct copy */
      stats_collect (map_fd, map_type, &record);
      stats_print (&record, &prev);
      sleep (interval);
    }
}

/* It is the userspace program's responsibility to know what map it is reading
 * and know the value size Here get bpf_map_info and check if it matches
 * expectations. */
static int
__check_map_fd_info (int map_fd, struct bpf_map_info *info,
                     struct bpf_map_info *exp)
{
  __u32 info_len = sizeof (*info);
  int err;

  if (map_fd < 0)
    return EXIT_FAILURE;

  /* BPF-info via bpf syscall */
  err = bpf_obj_get_info_by_fd (map_fd, info, &info_len);
  if (err)
    {
      fprintf (stderr, "ERR: %s() can't get info - %s\n", __func__,
               strerror (errno));
      return EXIT_FAIL_BPF;
    }

  if (exp->max_entries && exp->max_entries != info->key_size)
    {
      fprintf (stderr,
               "ERR: %s() "
               "Map max_entries(%d) mismatch expected size(%d)\n",
               __func__, info->max_entries, exp->max_entries);
      return EXIT_FAIL;
    }

  if (exp->key_size && exp->key_size != info->key_size)
    {
      fprintf (stderr,
               "ERR: %s() "
               "Map key size(%d) mismatch expected size(%d)\n",
               __func__, info->key_size, exp->key_size);
      return EXIT_FAIL;
    }

  if (exp->value_size && exp->key_size != info->key_size)
    {
      fprintf (stderr,
               "ERR: %s() "
               "Map value size(%d) mismatch expected size(%d)\n",
               __func__, info->value_size, exp->value_size);
      return EXIT_FAIL;
    }

  if (exp->type && exp->type != info->type)
    {
      fprintf (stderr,
               "ERR: %s() "
               "Map type(%d) mismatch expected type(%d)\n",
               __func__, info->type, exp->type);
      return EXIT_FAIL;
    }

  return EXIT_OK;
}

int
main (int argc, char **argv)
{
  struct bpf_map_info map_expect = { 0 };
  struct bpf_map_info info = { 0 };
  struct xdp_kern *bpf_obj;
  int stats_map_fd;
  int interval = 2;
  int err;
  int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s <iface>\n", argv[0]);
      return EXIT_FAILURE;
    }

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

  obj = xdp_kern__open_and_load ();
  if (!obj)
    {
      fprintf (stderr, "Failed to load BPF object\n");
      return EXIT_FAIL_BPF;
    }

  /* Attach BPF to network interface */
  int xdp_fd;
  xdp_fd = bpf_program__fd (obj->progs.xdp_stats1_func);

  if (xdp_fd < 0)
    {
      fprintf (stderr, "Failed to get program file descriptor\n");
      goto cleanup;
    }
  err = bpf_xdp_attach (ifindex, xdp_fd, flags, NULL);
  if (err)
    {
      fprintf (stderr, "failed to attach BPF to iface %s (%d): %d\n", iface,
               ifindex, err);
      goto cleanup;
    }

  /* Remove BPF from network interface */
  signal (SIGINT, cleanup_xdp);
  signal (SIGTERM, cleanup_xdp);

  stats_map_fd = bpf_map__fd (obj->maps.xdp_stats_map);
  if (stats_map_fd < 0)
    {
      fprintf (stderr, "Failed to load stats map\n");
      xdp_detach_prog ();
      return EXIT_FAIL_BPF;
    }

  map_expect.key_size = sizeof (__u32);
  map_expect.value_size = sizeof (struct datarec);
  map_expect.max_entries = XDP_ACTION_MAX;
  err = __check_map_fd_info (stats_map_fd, &info, &map_expect);
  if (err)
    {
      fprintf (stderr, "ERR: map via FD not compatible\n");
      return err;
    }

  printf ("\nCollecting stats from BPF map\n");
  printf (" - BPF map (bpf_map_type:%d) id:%d name:%s"
          " key_size:%d value_size:%d max_entries:%d\n",
          info.type, info.id, info.name, info.key_size, info.value_size,
          info.max_entries);

  stats_poll (stats_map_fd, info.type, interval);

cleanup:
  xdp_kern__destroy (obj);
  if (err)
    return EXIT_FAILURE;
  return EXIT_OK;
}