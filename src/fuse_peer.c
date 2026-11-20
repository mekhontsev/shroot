#define _GNU_SOURCE
#include "fuse_peer.h"
#include "fuse_transport.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct md_fuse_peer {
    struct md_fuse_connection *connection;
    atomic_uint owners;
    int fd;
};

static void release(struct md_fuse_peer *p) {
    if (atomic_fetch_sub_explicit(&p->owners,1,memory_order_acq_rel)!=1) return;
    close(p->fd); md_fuse_connection_release(p->connection); free(p);
}

/* Never block the filesystem worker on a document provider. Drain both
 * directions even when the peer backpressures a partially written request. */
static void *pump(void *arg) {
    struct md_fuse_peer *p=arg;
    unsigned char *out=malloc(MD_FUSE_PACKET_MAX),*in=malloc(MD_FUSE_PACKET_MAX);
    size_t sent=0,got=0,length=0,need=sizeof(struct fuse_out_header);
    int error=out && in ? 0 : -ENOMEM;
    while (!error) {
        struct pollfd fds[]={{p->fd,POLLIN|(length ? POLLOUT : 0),0},
            {length ? -1 : md_fuse_connection_descriptor(p->connection),POLLIN,0}};
        if (poll(fds,2,-1)<0) { if (errno==EINTR) continue; error=-errno; break; }
        if (fds[0].revents&POLLIN) {
            ssize_t n=recv(p->fd,in+got,need-got,MSG_DONTWAIT);
            if (!n) break;
            if (n<0 && errno!=EAGAIN && errno!=EINTR) { error=-errno; break; }
            if (n>0) got+=(size_t)n;
            if (got==need) {
                struct fuse_out_header header;
                memcpy(&header,in,sizeof(header));
                if (header.len<sizeof(header) || header.len>MD_FUSE_PACKET_MAX) { error=-EPROTO; break; }
                need=header.len;
                if (got==need) {
                    long result=md_fuse_connection_write(p->connection,in,got);
                    if (result<0 && result!=-ENOENT) { error=(int)result; break; }
                    got=0; need=sizeof(header);
                }
            }
        }
        if (fds[0].revents&(POLLERR|POLLNVAL) || ((fds[0].revents&POLLHUP) && !(fds[0].revents&POLLIN))) break;
        if (fds[0].revents&POLLOUT) {
            ssize_t n=send(p->fd,out+sent,length-sent,MSG_DONTWAIT|MSG_NOSIGNAL);
            if (n<0 && errno!=EINTR && errno!=EAGAIN) { error=-errno; break; }
            if (n>0) sent+=(size_t)n;
            if (sent==length) { md_fuse_connection_read_commit(p->connection,length); sent=length=0; }
        }
        if (fds[1].revents) {
            long n=md_fuse_connection_read(p->connection,out,MD_FUSE_PACKET_MAX);
            if (n==-EAGAIN) continue;
            if (n<=0) { error=n ? (int)n : -EIO; break; }
            length=(size_t)n;
        }
    }
    md_fuse_connection_abort(p->connection,error ? error : -ENOTCONN);
    free(in); free(out); release(p); return NULL;
}

int md_fuse_peer_start(const char *name,struct md_fuse_connection *c,struct md_fuse_peer **owner) {
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    if (!name || (*name!='/' && (*name!='@' || !name[1]))) return -EINVAL;
    size_t n=strlen(name);
    if (n>=sizeof(addr.sun_path)) return -ENAMETOOLONG;
    memcpy(addr.sun_path,name,n);
    if (*name=='@') addr.sun_path[0]=0; else ++n;
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<0) return -errno;
    if (connect(fd,(struct sockaddr *)&addr,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+n))) {
        int error=-errno; close(fd); return error;
    }
    /* Abstract names have no filesystem owner. A stale launch description
     * must not connect to a replacement listener owned by another UID. */
    struct ucred peer; socklen_t size=sizeof(peer);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)) {
        int error=-errno; close(fd); return error;
    }
    if (size!=sizeof(peer) || peer.uid!=geteuid()) { close(fd); return -EACCES; }
    struct md_fuse_peer *p=calloc(1,sizeof(*p));
    if (!p) { close(fd); return -ENOMEM; }
    p->fd=fd; p->connection=md_fuse_connection_retain(c);
    atomic_init(&p->owners,2);
    pthread_t thread;
    int error=pthread_create(&thread,NULL,pump,p);
    if (error) { md_fuse_connection_release(p->connection); close(fd); free(p); return -error; }
    pthread_detach(thread); *owner=p; return 0;
}
void md_fuse_peer_close(struct md_fuse_peer *p) {
    if (!p) return;
    shutdown(p->fd,SHUT_RDWR); release(p);
}
