#ifndef MD_DIRECTORY_CURSOR_H
#define MD_DIRECTORY_CURSOR_H

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

/* A directory cookie is opaque: clamping it is not a successful commit. */
static inline int md_directory_seek_exact(int fd,off_t cookie) {
    off_t actual=lseek(fd,cookie,SEEK_SET);
    return actual<0 ? -errno : actual!=cookie ? -EIO : 0;
}
#endif
