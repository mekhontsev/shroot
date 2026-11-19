#define _GNU_SOURCE
#include "fd_filter.h"
#include "fd_client.h"
#include <errno.h>

long md_fd_filter_prepared(unsigned selectors) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long ready=md_fd_control(MD_FD_SELECTOR_QUERY,kind,-1,0);
        if (ready<=0) return ready;
    }
    return 1;
}

static long arm(enum md_fd_selector_kind kind,int fd,unsigned operation) {
    if (fd< -1 || kind<0 || kind>=MD_FD_SELECTOR_KINDS) return -EINVAL;
#ifdef MD_USE_LIBC
    (void)operation;
    return -ENOTSUP;
#else
    for (;;) {
        long result=md_fd_control(operation,kind,fd,0);
        if (result<=0) return result;
        /* EVENT_WAIT: a retiring private helper can temporarily reject TSYNC.
         * Retry only after its exit; incompatible live filters remain errors. */
        result=md_fd_control(MD_FD_SELECTOR_EXIT,(uint64_t)result,0,0);
        if (result<0) return result;
    }
#endif
}
long md_fd_filter_arm(enum md_fd_selector_kind kind, int fd) {
    return fd<0 ? -EINVAL : arm(kind,fd,MD_FD_SELECTOR_INSTALL);
}
static long arm_mask(unsigned selectors,int fd) {
    if (selectors&~((1U<<MD_FD_SELECTOR_KINDS)-1)) return -EINVAL;
    for (unsigned kind=0;kind<MD_FD_SELECTOR_KINDS;++kind) if (selectors&(1U<<kind)) {
        long error=arm((enum md_fd_selector_kind)kind,fd,MD_FD_SELECTOR_INSTALL);
        if (error) return error;
    }
    return 0;
}
long md_fd_filter_arm_mask(unsigned selectors,int fd) {
    return fd<0 ? -EINVAL : arm_mask(selectors,fd);
}
long md_fd_filter_prepare_all(unsigned selectors) { return arm_mask(selectors,-1); }
long md_fd_filter_before_allocation(unsigned selectors) {
    return selectors&((1U<<MD_FD_SELECTOR_PROC)|(1U<<MD_FD_SELECTOR_IOCTL))
        ? arm(MD_FD_SELECTOR_IOCTL,-1,MD_FD_SELECTOR_BEFORE_ALLOCATION) : 0;
}
long md_fd_filter_prepare_sandbox(void) {
    /* A thread-local policy can split a live group's kernel filter chain.
     * Prepare future typed FDs before that split; ordinary single-threaded
     * and synchronized policy installation retain selective activation. */
    return md_fd_filter_prepare_all(MD_FD_SANDBOX_SELECTORS);
}
