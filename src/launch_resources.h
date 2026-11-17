#ifndef SHROOT_LAUNCH_RESOURCES_H
#define SHROOT_LAUNCH_RESOURCES_H
#include "arguments.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

/* Launch-only custody. The descriptors are opaque resources, not guest IO. */
static inline int md_owner_fd(const char *value) {
    unsigned long fd = 0;
    if (!value || !*value) return -EINVAL;
    for (; *value; ++value) {
        if (*value < '0' || *value > '9' || fd > (INT_MAX - (unsigned)(*value - '0')) / 10U)
            return -EINVAL;
        fd = fd * 10 + (unsigned)(*value - '0');
    }
    return fd < 3 ? -EINVAL : (int)fd;
}
static inline int md_owner_fds_add(struct md_arguments *owners, char *value) {
    int fd = md_owner_fd(value);
    if (fd < 0) return fd;
    long flags = RAW3(fcntl, fd, F_GETFD, 0);
    if (flags < 0) return (int)flags;
    for (size_t i = 0; i < owners->count; ++i)
        if (md_owner_fd(owners->values[i]) == fd) return -EINVAL;
    int r = md_arguments_reserve(owners, owners->count + 1);
    if (!r) owners->values[owners->count++] = value;
    return r;
}
static inline void md_owner_fds_close(const struct md_arguments *owners) {
    for (size_t i = 0; i < owners->count; ++i) RAW1(close, md_owner_fd(owners->values[i]));
}
#endif
