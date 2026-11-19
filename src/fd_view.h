#ifndef MD_FD_VIEW_H
#define MD_FD_VIEW_H
#include <stdatomic.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>

/* Value-only authority published under an exclusive descriptor-table turn.
 * The resident caller defers signals. Stops, borrowed execution and every new
 * owner request revoke the view before another actor can replace the slot.
 * Mutable OFD state stays in the kernel; no offset/status/size is cached. */
#define MD_FD_VIEW_RESULT UINT32_MAX
#define MD_FD_VIEW_UNTRACKED (UINT32_MAX-1)
/* Exact low slots, then one bit per power-of-two interval. A clear bit
 * certifies absence; a set bit never establishes that an FD is tracked. */
enum { MD_FD_EXACT_SLOTS=32, MD_FD_WIDE_GROUPS=26 };
static inline unsigned md_fd_group(unsigned fd) {
    return fd<MD_FD_EXACT_SLOTS ? fd
        : MD_FD_EXACT_SLOTS+__builtin_clz((unsigned)MD_FD_EXACT_SLOTS)-__builtin_clz(fd);
}
struct md_fd_absence {
    uint64_t occupied,checkable;
    uint64_t carrier_device,carrier_inode;
    int source,result;
    unsigned duplicates,carrier_kinds;
};
static inline unsigned md_fd_kind_bit(unsigned mode) { return 1u<<((mode&S_IFMT)>>12); }
struct md_fd_view {
    atomic_uint descriptor;
    union {
        struct { unsigned flags,kind; };
        struct md_fd_absence absence;
    };
};
static inline void md_fd_view_revoke(struct md_fd_view *v) {
    atomic_store_explicit(&v->descriptor,0,memory_order_release);
}
static inline void md_fd_view_publish(struct md_fd_view *v,unsigned descriptor,unsigned flags,unsigned kind) {
    v->flags=flags; v->kind=kind;
    atomic_store_explicit(&v->descriptor,descriptor,memory_order_release);
}
static inline void md_fd_view_publish_absence(struct md_fd_view *v,const struct md_fd_absence *absence) {
    v->absence=*absence;
    atomic_store_explicit(&v->descriptor,MD_FD_VIEW_UNTRACKED,memory_order_release);
}
static inline int md_fd_absent(const struct md_fd_absence *a,int fd) {
    return fd>=0 && (fd==a->source || fd==a->result || !(a->occupied & (UINT64_C(1)<<md_fd_group(fd))));
}
enum md_fd_view_route { MD_FD_VIA_OWNER, MD_FD_LOCAL, MD_FD_CHECK_ROUTE,
    MD_FD_CHECK_RESULT, MD_FD_CHECK_ROUTE_RESULT };
static inline uint64_t md_fd_suffix_conflicts(const struct md_fd_absence *a,int minimum) {
    return a->occupied & (UINT64_MAX<<md_fd_group((unsigned)minimum));
}
/* A successful allocating dup proves every skipped slot was occupied at its
 * linearization point. Never extend that evidence to a known hole higher up
 * or to slots below the minimum of the observed allocation. */
static inline uint64_t md_fd_checked_prefix(const struct md_fd_absence *a,int minimum,int result) {
    if (minimum<0 || result<=minimum) return 0;
    return a->checkable & md_fd_suffix_conflicts(a,minimum)
        & ((UINT64_C(1)<<md_fd_group((unsigned)result))-1);
}
static inline enum md_fd_view_route md_fd_view_native_mutation(const struct md_fd_view *v,long nr,const uint64_t args[6]) {
    if (nr!=SYS_close && nr!=SYS_dup && nr!=SYS_dup3 && nr!=SYS_fcntl) return 0;
    if (nr==SYS_fcntl && (unsigned)args[1]!=F_DUPFD && (unsigned)args[1]!=F_DUPFD_CLOEXEC) return 0;
    if (atomic_load_explicit(&v->descriptor,memory_order_acquire)!=MD_FD_VIEW_UNTRACKED
            || !md_fd_absent(&v->absence,(int)args[0])) return 0;
    if (nr==SYS_close) return MD_FD_LOCAL;
    enum md_fd_view_route neutral=v->absence.duplicates ? MD_FD_LOCAL : MD_FD_CHECK_ROUTE;
    if (nr==SYS_dup3) return md_fd_absent(&v->absence,(int)args[1]) ? neutral : MD_FD_VIA_OWNER;
    /* An allocating dup may choose ANY free slot at or above its minimum.
     * Even an uncertain/stale annotation in that suffix needs its owner. */
    int minimum=nr==SYS_dup ? 0 : (int)args[2];
    if (minimum<0) return MD_FD_VIA_OWNER;
    uint64_t conflicts=md_fd_suffix_conflicts(&v->absence,minimum);
    if (!conflicts) return neutral;
    if (conflicts & ~v->absence.checkable) return MD_FD_VIA_OWNER;
    return v->absence.duplicates ? MD_FD_CHECK_RESULT : MD_FD_CHECK_ROUTE_RESULT;
}
static inline int md_fd_slot_query(long number,unsigned command,uint64_t value,unsigned flags) {
    return number==SYS_fcntl && (command==F_GETFD || (command==F_SETFD && (value&FD_CLOEXEC)==flags));
}
/* A slot-only view (kind zero) cannot access the underlying OFD. */
static inline int md_fd_view_query(long number,const uint64_t args[6],unsigned kind,unsigned flags) {
    if (number==SYS_fcntl) return md_fd_slot_query(number,(unsigned)args[1],args[2],flags)
        || (kind && (unsigned)args[1]==F_GETFL);
    if (kind!=S_IFREG) return 0;
    return number==SYS_lseek || (number==SYS_ioctl && (unsigned)args[1]==FIONREAD);
}
#endif
