#ifndef MD_SOCKET_ABI_H
#define MD_SOCKET_ABI_H
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* AArch64 syscall buffers, not libc's narrower POSIX length fields. These
 * layouts also describe messages injected into a guest by a task helper. */
struct md_msghdr {
    void *msg_name;
    uint32_t msg_namelen, reserved0;
    struct iovec *msg_iov;
    uint64_t msg_iovlen;
    void *msg_control;
    uint64_t msg_controllen;
    int32_t msg_flags;
    uint32_t reserved1;
};
struct md_mmsghdr { struct md_msghdr msg_hdr; uint32_t msg_len, reserved; };
struct md_cmsghdr { uint64_t cmsg_len; int32_t cmsg_level, cmsg_type; };
_Static_assert(sizeof(struct md_msghdr)==56, "AArch64 msghdr size");
_Static_assert(offsetof(struct md_msghdr,msg_iovlen)==24, "AArch64 vector count offset");
_Static_assert(offsetof(struct md_msghdr,msg_controllen)==40, "AArch64 control size offset");
_Static_assert(sizeof(struct md_mmsghdr)==64, "AArch64 mmsghdr stride");
_Static_assert(sizeof(struct md_cmsghdr)==16, "AArch64 control header size");

#define MD_CMSG_ALIGN(n) (((size_t)(n)+7U)&~(size_t)7U)
#define MD_CMSG_LEN(n) (sizeof(struct md_cmsghdr)+(size_t)(n))
#define MD_CMSG_SPACE(n) (sizeof(struct md_cmsghdr)+MD_CMSG_ALIGN(n))
#define MD_CMSG_DATA(h) ((unsigned char *)(h)+sizeof(struct md_cmsghdr))
static inline struct md_cmsghdr *md_cmsg_first(const struct md_msghdr *m) {
    return m->msg_controllen<sizeof(struct md_cmsghdr) ? NULL : m->msg_control;
}
#define MD_CMSG_FIRSTHDR(m) md_cmsg_first(m)
#endif
