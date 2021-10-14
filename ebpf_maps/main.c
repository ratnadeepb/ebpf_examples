// https://hechao.li/2019/03/19/Use-Map-in-Map-in-BPF-programs-via-Libbpf/
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

const char *outer_map_name = "outer_map";

static struct bpf_object *
get_bpf_object(char *path)
{
    struct bpf_object *obj = bpf_object__open(path);
    if (!obj)
    {
        fprintf(stderr, "failed to load bpf object from %s\n", path);
        return NULL;
    }

    struct bpf_program *prog;
    enum bpf_prog_type prog_type;
    enum bpf_attach_type expected_attach_type;
    bpf_object__for_each_program(prog, obj)
    {
        const char *prog_name = bpf_program__title(prog, false);
        int err = libbpf_prog_type_by_name(prog_name, &prog_type, &expected_attach_type);
        if (err < 0)
        {
            fprintf(stderr, "failed to guess program name based on section name: %s\n", prog_name);
            return NULL;
        }
        bpf_program__set_type(prog, prog_type);
        bpf_program__set_expected_attach_type(prog, expected_attach_type);
    }

    return obj;
}

int load(struct bpf_object *obj)
{
    struct bpf_map *outer_map = bpf_object__find_map_by_name(obj, outer_map_name);
    if (outer_map == NULL)
    {
        fprintf(stderr, "failed to find outer map\n");
        return EXIT_FAILURE;
    }

    // create a dummy inner map
    int inner_map_fd = bpf_create_map(
        BPF_MAP_TYPE_HASH, //type
        sizeof(__u32),     // key size
        sizeof(__u32),     // value size
        8,                 // max entries
        0                  // flag
    );

    // set inner map fd to outer map
    if (bpf_map__set_inner_map_fd(outer_map, inner_map_fd) != 0)
    {
        close(inner_map_fd);
        fprintf(stderr, "failed to set inner fd!\n");
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj))
    {
        close(inner_map_fd);
        fprintf(stderr, "failed to load bpf object: %ld\n", libbpf_get_error(obj));
        return EXIT_FAILURE;
    }

    // inner map is not required
    // it was created to make the verifier happy only
    close(inner_map_fd);
    return EXIT_SUCCESS;
}

int get_map_fd(struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (map == NULL)
    {
        fprintf(stderr, "failed to find map %s\n", name);
        return -1;
    }
    return bpf_map__fd(map);
}

/* insert into outer map */
int insert(struct bpf_object *obj)
{
    int outer_map_fd = get_map_fd(obj, outer_map_name);
    if (outer_map_fd < 0)
    {
        fprintf(stderr, "failed to get outer map\n");
        return EXIT_FAILURE;
    }

    int ret = 0;
    int inner_map_fd = bpf_create_map_name(
        BPF_MAP_TYPE_HASH, // type
        "inner_map",       // name
        sizeof(__u32),     // key size
        sizeof(__u32),     // value size
        8,                 // max entries
        0                  // flag
    );
    if (inner_map_fd < 0)
    {
        fprintf(stderr, "failed to create inner map\n");
        return EXIT_FAILURE;
    }

    const __u32 inner_key = 12;
    const __u32 inner_value = 34;
    if (bpf_map_update_elem(inner_map_fd, &inner_key, &inner_value, 0))
    {
        fprintf(stderr, "failed to insert into inner map\n");
        return EXIT_FAILURE;
    }

    const __u32 outer_key = 42;
    if (bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0))
    {
        fprintf(stderr, "failed to insert into outer map\n");
        return EXIT_FAILURE;
    }
    close(inner_map_fd);
    return EXIT_SUCCESS;
}

int lookup(struct bpf_object *obj)
{
    int outer_map_fd = get_map_fd(obj, outer_map_name);
    if (outer_map_fd < 0)
    {
        fprintf(stderr, "failed to get outer map\n");
        return EXIT_FAILURE;
    }
    const __u32 outer_key = 42;
    __u32 inner_map_id;
    if (bpf_map_lookup_elem(outer_map_fd, &outer_key, &inner_map_id))
    {
        fprintf(stderr, "Failed to find inner map id!\n");
        return EXIT_FAILURE;
    }

    int inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    if (inner_map_fd < 0)
    {
        fprintf(stderr, "Failed to find inner map fd!\n");
        return EXIT_FAILURE;
    }

    const __u32 inner_key = 12;
    __u32 inner_value;
    int ret;
    if (bpf_map_lookup_elem(inner_map_fd, &inner_key, &inner_value))
    {
        fprintf(stderr, "Failed to look up the value in inner map!\n");
        ret = EXIT_FAILURE;
    }
    else
    {
        fprintf(stdout, "Inner value is %u!\n", inner_value);
        ret = EXIT_SUCCESS;
    }
    close(inner_map_fd);
    return ret;
}

int delete (struct bpf_object *obj)
{
    int outer_map_fd = get_map_fd(obj, outer_map_name);
    if (outer_map_fd < 0)
    {
        fprintf(stderr, "failed to get outer map\n");
        return EXIT_FAILURE;
    }
    // const __u32
}