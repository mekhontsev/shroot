#ifndef MD_TEST_CAPABILITIES_H
#define MD_TEST_CAPABILITIES_H
#include <assert.h>
#include <linux/capability.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Exercise denial under both unprivileged hosts and logical/native root. */
static inline void md_test_capabilities_suspend(uint64_t mask,struct __user_cap_data_struct saved[2]) {
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3};
    assert(!syscall(SYS_capget,&header,saved));
    struct __user_cap_data_struct next[2]={saved[0],saved[1]};
    next[0].effective&=~(uint32_t)mask;
    next[1].effective&=~(uint32_t)(mask>>32);
    assert(!syscall(SYS_capset,&header,next));
}
static inline void md_test_capabilities_restore(const struct __user_cap_data_struct saved[2]) {
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3};
    assert(!syscall(SYS_capset,&header,saved));
}
#endif
