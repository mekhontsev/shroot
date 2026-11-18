#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <limits.h>
#include "../src/statx_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static void empty_readlink(int fd) {
    char text[32];
    errno=0; assert(readlinkat(fd,"",text,sizeof(text))==-1 && errno==ENOENT);
    errno=0; assert(readlinkat(fd,"",text,0)==-1 && errno==EINVAL);
}
int test_native_metadata_guest(const char *directory) {
    char path[PATH_MAX];
    assert(snprintf(path,sizeof(path),"%s/native-mode-XXXXXX",directory)<(int)sizeof(path));
    int fd=mkstemp(path); assert(fd>=0);
    assert(!unlink(path));
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int reference=open(path,O_PATH|O_CLOEXEC); assert(reference>=0);
    snprintf(path,sizeof(path),"/proc/self/fd/%d",reference);
    assert(!chmod(path,0640));
    struct stat st; assert(!fstat(fd,&st) && (st.st_mode&0777)==0640 && !st.st_nlink);
    for (unsigned i=0;i<16;++i) {
        struct timespec times[2]={{123456+i,0},{234567+i,0}};
        unsigned mode=i&1 ? 0600 : 0640;
        assert(!fchmod(fd,mode) && !fchown(fd,(uid_t)-1,(gid_t)-1));
        assert(!futimens(fd,times));
        assert(!fsync(fd) && !fdatasync(fd));
        assert(!fstat(fd,&st) && (st.st_mode&0777)==mode && st.st_mtim.tv_sec==times[1].tv_sec);
        errno=0; assert(syscall(SYS_fchmod,reference,0600)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_fchown,reference,(uid_t)-1,(gid_t)-1)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_utimensat,reference,0,times,0)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_fsync,reference)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_fdatasync,reference)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_syncfs,reference)==-1 && errno==EBADF);
        errno=0; assert(syscall(SYS_utimensat,fd,0,1,0)==-1 && errno==EFAULT);
    }
    close(reference); close(fd);
    fd=syscall(SYS_memfd_create,"metadata",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
    assert(!ftruncate(fd,6) && !fstat(fd,&st));
    empty_readlink(fd);
    for (unsigned i=0;i<2;++i) {
        struct md_statx x={0}; unsigned mask=STATX_ALL|(i ? STATX_MNT_ID : 0);
        int r=syscall(SYS_statx,fd,"",AT_EMPTY_PATH,mask,&x);
        printf("memfd statx mask=%x result=%d errno=%d returned=%x mount=%llu\n",mask,r,errno,x.stx_mask,(unsigned long long)x.stx_mnt_id);
        fflush(stdout); assert(!r && x.stx_size==6 && x.stx_ino==st.st_ino);
    }
    close(fd);
    int pipefd[2]; assert(!pipe2(pipefd,O_CLOEXEC));
    empty_readlink(pipefd[0]); empty_readlink(pipefd[1]); close(pipefd[0]); close(pipefd[1]);
    puts("PASS native metadata: anonymous memfd statx, O_PATH proc chmod and empty-path non-links"); return 0;
}
