#ifndef MD_FILESYSTEM_IOCTL_H
#define MD_FILESYSTEM_IOCTL_H
#include <linux/fs.h>
#include <asm/ioctls.h>

/* Filesystem metadata belongs to the selected provider, not to its Android
 * storage inode. Opening a devpts peer also retains its mount identity;
 * ordinary device, terminal and socket commands stay separate. */
static inline int md_filesystem_ioctl_opens(unsigned command) {
    return command==TIOCGPTPEER;
}
#define MD_FILESYSTEM_METADATA_COMMANDS(X) X(FS_IOC_GETFLAGS) X(FS_IOC_SETFLAGS) \
    X(FS_IOC_GETVERSION) X(FS_IOC_SETVERSION) X(FS_IOC_FSGETXATTR) X(FS_IOC_FSSETXATTR)
static inline int md_filesystem_ioctl_command(unsigned command) {
#define MATCH(value) command==(value) ||
    return MD_FILESYSTEM_METADATA_COMMANDS(MATCH) md_filesystem_ioctl_opens(command);
#undef MATCH
}
static inline int md_filesystem_ioctl_writes(unsigned command) {
    return command==FS_IOC_SETFLAGS || command==FS_IOC_SETVERSION || command==FS_IOC_FSSETXATTR;
}
#endif
