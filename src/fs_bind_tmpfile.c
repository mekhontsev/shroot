#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "host_open.h"
#include "inode_internal.h"
#include "temporary_directory.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

/* This name exists only inside a store-private leased directory. The data FD
 * never changes; the first publication moves the name, not the contents. */
static const char leaf[]="unpublished";

int md_bind_tmpfile_parent(int store,int create) {
    int mounts=md_private_directory_open(store,"mounts",create);
    if (mounts<0) return mounts;
    int parent=md_private_directory_open(mounts,"tmpfiles",create);
    close(mounts); return parent;
}

static int same_attribute(int a,int b,const char *name) {
    char x[512],y[sizeof(x)];
    ssize_t n=fgetxattr(a,name,x,sizeof(x)); int e=errno;
    ssize_t m=fgetxattr(b,name,y,sizeof(y));
    if (n<0 || m<0)
        return n==m && e==errno && (e==ENODATA || e==EOPNOTSUPP);
    return n==m && !memcmp(x,y,n);
}
static int compatible(int reference,int fd) {
    struct md_statx a,b;
    if (syscall(SYS_statx,reference,"",AT_EMPTY_PATH,STATX_BASIC_STATS|STATX_MNT_ID,&a)
            || syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS|STATX_MNT_ID,&b)) return -errno;
    if (!(a.stx_mask&b.stx_mask&STATX_MNT_ID) || a.stx_mnt_id!=b.stx_mnt_id
            || a.stx_uid!=b.stx_uid || a.stx_gid!=b.stx_gid || a.stx_mode!=b.stx_mode
            || !same_attribute(reference,fd,"security.selinux")
            || !same_attribute(reference,fd,"system.posix_acl_access")) return -EOPNOTSUPP;
    return 0;
}
int md_bind_tmpfile_open(struct md_inode_store *store,int dir,int flags,mode_t mode,int *lease) {
    /* The actual directory decides whether creation, the access mode and
     * inherited permissions are allowed. Do not grant private-store rights
     * in place of a denied host open. Exclusive files are never publishable. */
    int fd=openat(dir,".",flags|O_CLOEXEC,mode);
    if (fd<0) return -errno;
    if (flags&O_EXCL) return fd;
    int parent=md_bind_tmpfile_parent(store->lifetime->root,1);
    int stage=parent<0 ? parent : md_temporary_directory_create(parent,!store->tmpfile_parent_collected);
    if (parent>=0) close(parent);
    if (stage<0) { close(fd); return stage; }
    store->tmpfile_parent_collected=1;
    int data=openat(stage,leaf,(flags&~O_TMPFILE)|O_CLOEXEC|O_CREAT|O_EXCL|O_NOFOLLOW,mode);
    int error=data<0 ? -errno : compatible(fd,data);
    close(fd);
    if (error) {
        if (data>=0) close(data);
        md_temporary_directory_release(stage); return error;
    }
    *lease=stage; return data;
}
int md_bind_tmpfile_pending(const struct md_fs_anchor *a) {
    struct stat st;
    if (fstatat(a->tmpfile_lease,leaf,&st,AT_SYMLINK_NOFOLLOW)) return errno==ENOENT ? 0 : -errno;
    return (st.st_ino==a->inode && st.st_dev==a->device) ? 1 : -ESTALE;
}
int md_bind_tmpfile_publish(const struct md_fs_anchor *a,int dir,const char *name) {
    int pending=md_bind_tmpfile_pending(a);
    return pending<=0 ? (pending ? pending : -EOPNOTSUPP)
        : (int)md_host_rename(a->tmpfile_lease,leaf,dir,name,RENAME_NOREPLACE);
}
