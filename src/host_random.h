#ifndef MD_HOST_RANDOM_H
#define MD_HOST_RANDOM_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>

static inline int md_random_bytes(void *out,size_t size) {
#ifdef MD_HAVE_ARC4RANDOM
    arc4random_buf(out,size);
#else
    unsigned char *p=out;
    size_t left=size;
    while (left) {
        ssize_t n=getrandom(p,left,0);
        if (n<0) { if (errno==EINTR) continue; return -errno; }
        if (!n) return -EIO;
        p+=n; left-=(size_t)n;
    }
#endif
    return 0;
}
static inline int md_random_u32(uint32_t *out) {
#ifdef MD_HAVE_ARC4RANDOM
    *out=arc4random();
    return 0;
#else
    return md_random_bytes(out,sizeof(*out));
#endif
}
static inline int md_random_bounded(uint32_t bound,uint32_t *out) {
    if (!bound) return -EINVAL;
#ifdef MD_HAVE_ARC4RANDOM
    *out=arc4random_uniform(bound);
#else
    /* Reject the incomplete residue class instead of biasing a port range. */
    uint32_t value,minimum=(uint32_t)-bound%bound;
    do {
        int error=md_random_u32(&value);
        if (error) return error;
    } while (value<minimum);
    *out=value%bound;
#endif
    return 0;
}
#endif
