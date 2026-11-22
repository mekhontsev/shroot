#define _GNU_SOURCE
#include "device_tree.h"
#include "fuse_device.h"
#include "kmsg_device.h"
#include "network_tun.h"
#include "render_device.h"
#include "fs_mount_internal.h"
#include "inode_lifetime.h"
#include "inode_internal.h"
#include "file_open.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static int portable_nodes(struct md_filesystem *fs,struct md_provider_tree *dev,int parent,
        struct md_inode_store **out) {
    int error=md_inode_store_transient(parent,md_mount_namespace_owner(fs->mounts),out);
    if (error) return error;
    md_inode_store_lifetime(*out)->filesystem_kind=MD_FILESYSTEM_TMPFS;
    error=md_inode_operation_window_begin(*out);
    if (error) return error;
    const char *path; uint64_t device;
    for (unsigned i=0;!error && md_open_device_node(i,&path,&device);++i)
        error=md_inode_mknod(*out,MD_INODE_ROOT,path+5,S_IFCHR|0666,device);
    int end=md_inode_operation_window_end(*out);
    if (!error) error=end;
    for (unsigned i=0;!error && md_open_device_node(i,&path,&device);++i)
        error=md_provider_placeholder(md_provider_tree_root(dev),path+5,0600);
    return error;
}
static int attach_nodes(struct md_filesystem *fs,struct md_inode_store *store,
        const struct md_mount_source *shm) {
    const char *path; uint64_t device;
    unsigned nodes=0;
    while (md_open_device_node(nodes,&path,&device)) ++nodes;
    unsigned count=nodes+1;
    struct md_mount_source sources[count];
    struct md_view_location targets[count];
    struct md_mount_attachment items[count];
    for (unsigned i=0;i<count;++i) {
        sources[i]=(struct md_mount_source){.fd=-1,.backing=MD_MOUNT_INODE,
            .storage=md_inode_store_lifetime(store),.policy=MD_MOUNT_NOSUID|MD_MOUNT_NOEXEC};
        targets[i]=(struct md_view_location){.fd=-1,.parent=-1};
        items[i]=(struct md_mount_attachment){&sources[i],&targets[i]};
    }
    sources[nodes]=*shm;
    int error=md_inode_read_scope_begin(store);
    if (!error) {
        for (unsigned i=0;!error && md_open_device_node(i,&path,&device);++i) {
            int fd=md_inode_open(store,MD_INODE_ROOT,path+5,O_PATH|O_CLOEXEC,0);
            if (fd<0) error=fd; else sources[i].fd=fd;
        }
        int end=md_inode_read_scope_end(store);
        if (!error) error=end;
    }
    for (unsigned i=0;!error && md_open_device_node(i,&path,&device);++i)
        error=md_view_walk(fs,-1,NULL,path,1,0,MD_VIEW_MOUNT_TARGET,&targets[i]);
    if (!error) error=md_view_walk(fs,-1,NULL,"/dev/shm",1,0,MD_VIEW_MOUNT_TARGET,&targets[nodes]);
    if (!error) error=md_view_attach_sources(fs,items,count,NULL);
    for (unsigned i=0;i<count;++i) {
        md_view_location_close(&targets[i]);
        if (i<nodes && sources[i].fd>=0) close(sources[i].fd);
    }
    return error;
}
int md_fs_devices_prepare(struct md_filesystem *fs,int hide_native_input,struct md_provider_tree **out) {
    *out=NULL;
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_provider_tree *dev=md_device_tree_new(parent,hide_native_input);
    struct md_inode_store *nodes=NULL;
    int error=dev ? portable_nodes(fs,dev,parent,&nodes) : -errno;
    close(parent);
    struct md_control_file fuse={0};
    if (!error) error=md_fuse_device_node(&fuse);
    if (!error) error=md_device_tree_publish(dev,"fuse",fuse);
    md_control_file_release(fuse);
    struct md_control_file tun={0};
    if (!error) error=md_tun_device_node(&tun);
    if (!error) error=md_device_tree_publish(dev,"net/tun",tun);
    md_control_file_release(tun);
    struct md_control_file kmsg={0};
    if (!error) error=md_kmsg_device_node(&kmsg);
    if (!error) error=md_device_tree_publish(dev,"kmsg",kmsg);
    md_control_file_release(kmsg);
    if (!error && fs->render_device.ops) {
        char path[32]; snprintf(path,sizeof(path),"dri/renderD%u",md_render_device_minor(fs->render_device));
        if (mkdirat(md_provider_tree_root(dev),"dri",0755)) error=-errno;
        if (!error) error=md_device_tree_publish(dev,path,fs->render_device);
    }
    /* /dev/shm keeps its inode namespace, independently of device discovery. */
    struct md_view_location shm={.fd=-1,.parent=-1};
    if (!error) error=md_view_walk(fs,-1,NULL,"/dev/shm",1,0,0,&shm);
    if (!error && !md_view_inode(shm.mount)) error=-EOPNOTSUPP;
    struct md_mount_source source={.fd=shm.fd,.backing=MD_MOUNT_INODE,
        .storage=shm.mount && shm.mount->storage ? shm.mount->storage : md_inode_store_lifetime(fs->store)};
    if (!error) error=md_fs_provider_mount(fs,dev,"/dev");
    if (!error) error=attach_nodes(fs,nodes,&source);
    md_view_location_close(&shm);
    md_inode_store_close(nodes);
    if (error) md_provider_tree_release(dev); else *out=dev;
    return error;
}
