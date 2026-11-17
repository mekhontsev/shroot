#ifndef SHROOT_LAUNCH_PATH_H
#define SHROOT_LAUNCH_PATH_H
#include "arguments.h"
#include "raw.h"
#include <errno.h>
#include <sys/mman.h>

/* Startup-only environment storage, released with the exec image. */
static inline long md_launch_path(const char *prefix, const char *path, char **out) {
    if (!prefix || !*prefix) return -EINVAL;
    if (!path) path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    size_t a = md_length(prefix), b = md_length(path);
    if (a > MD_EXEC_BYTES || b > MD_EXEC_BYTES - a || a + b > MD_EXEC_BYTES - 7) return -E2BIG;
    size_t size = a + b + 7;
    long mapping = RAW6(mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping < 0) return mapping;
    char *value = (char *)mapping;
    md_copy(value, size, "PATH=");
    md_append(value, size, prefix); md_append(value, size, ":"); md_append(value, size, path);
    *out = value; return 0;
}
#endif
