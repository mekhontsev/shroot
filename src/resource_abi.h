#ifndef MD_RESOURCE_ABI_H
#define MD_RESOURCE_ABI_H
#include <stdint.h>
#include <stddef.h>
#include <sys/resource.h>

/* AArch64 kernel output excludes libc extensions such as musl's reserved tail. */
struct md_rusage {
    struct { int64_t tv_sec, tv_usec; } ru_utime, ru_stime;
    int64_t ru_maxrss, ru_ixrss, ru_idrss, ru_isrss, ru_minflt, ru_majflt;
    int64_t ru_nswap, ru_inblock, ru_oublock, ru_msgsnd, ru_msgrcv, ru_nsignals;
    int64_t ru_nvcsw, ru_nivcsw;
};
_Static_assert(sizeof(struct md_rusage)==144, "Linux rusage result size");
_Static_assert(offsetof(struct md_rusage,ru_nivcsw)==136, "Linux rusage final field");

static inline struct md_rusage md_rusage_kernel(const struct rusage *r) {
    return (struct md_rusage){
        .ru_utime={r->ru_utime.tv_sec,r->ru_utime.tv_usec},
        .ru_stime={r->ru_stime.tv_sec,r->ru_stime.tv_usec},
        .ru_maxrss=r->ru_maxrss, .ru_ixrss=r->ru_ixrss, .ru_idrss=r->ru_idrss,
        .ru_isrss=r->ru_isrss, .ru_minflt=r->ru_minflt, .ru_majflt=r->ru_majflt,
        .ru_nswap=r->ru_nswap, .ru_inblock=r->ru_inblock, .ru_oublock=r->ru_oublock,
        .ru_msgsnd=r->ru_msgsnd, .ru_msgrcv=r->ru_msgrcv, .ru_nsignals=r->ru_nsignals,
        .ru_nvcsw=r->ru_nvcsw, .ru_nivcsw=r->ru_nivcsw};
}
#endif
