#ifndef MD_STATX_ABI_H
#define MD_STATX_ABI_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

/* Kernel wire layout, independent of libc's statx version. Some libcs still
 * expose the mount ID as padding and cannot coexist with <linux/stat.h>. */
struct md_statx_timestamp { int64_t tv_sec; uint32_t tv_nsec, reserved; };
struct md_statx {
    uint32_t stx_mask, stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid;
    uint16_t stx_mode, reserved0;
    uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct md_statx_timestamp stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id, reserved[13];
};
_Static_assert(sizeof(struct md_statx)==256, "Linux statx result size");
_Static_assert(offsetof(struct md_statx,stx_atime)==64, "Linux statx timestamp offset");
_Static_assert(offsetof(struct md_statx,stx_mnt_id)==144, "Linux statx mount ID offset");

#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ffU
#endif
#ifndef STATX_INO
#define STATX_INO 0x00000100U
#endif
#ifndef STATX_ALL
#define STATX_ALL 0x00000fffU
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif
#ifndef STATX__RESERVED
#define STATX__RESERVED 0x80000000U
#endif
#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT 0x00002000U
#endif
#endif
