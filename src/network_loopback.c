#define _GNU_SOURCE
#include "network_loopback.h"
#include "network_internal.h"
#include "temporary_directory.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>

static int directory(struct md_network_fabric *f) {
    if (f->loopback_directory) return 0;
    if (!f->loopback_parent) return -EACCES;
    int parent=open(f->loopback_parent,O_DIRECTORY|O_CLOEXEC);
    if (parent<0) return -errno;
    char name[64]; snprintf(name,sizeof(name),".shroot-loopback-%u",(unsigned)getuid());
    int owned=md_private_directory_open(parent,name,1);
    close(parent);
    if (owned<0) return owned;
    int root=md_temporary_directory_new(owned); close(owned);
    if (root<0) return root;
    f->loopback_directory=root+1; return 0;
}
int md_loopback_address(const struct md_network_fabric *f,uint64_t inode,struct md_inet_address logical,
        struct sockaddr_storage *out,socklen_t *length) {
    if (!f->loopback_directory) return -ENOENT;
    struct sockaddr_un un={.sun_family=AF_UNIX};
    char ip[INET6_ADDRSTRLEN];
    if (!inet_ntop(logical.ip.family,logical.ip.bytes,ip,sizeof(ip))) return -errno;
    int n=snprintf(un.sun_path,sizeof(un.sun_path),"/proc/self/fd/%d/%" PRIx64 "-%u-%s",
        f->loopback_directory-1,inode,ntohs(logical.port),ip);
    if (n<0 || (size_t)n>=sizeof(un.sun_path)) return -ENAMETOOLONG;
    *length=offsetof(struct sockaddr_un,sun_path)+n+1;
    memcpy(out,&un,*length); return 0;
}
int md_loopback_bind(struct md_network_fabric *f,int fd,uint64_t inode,struct md_inet_address logical) {
    int error=directory(f); if (error) return error;
    struct sockaddr_storage address; socklen_t size;
    error=md_loopback_address(f,inode,logical,&address,&size);
    return error ? error : bind(fd,(void *)&address,size) ? -errno : 0;
}
void md_loopback_unbind(struct md_network_fabric *f,uint64_t inode,struct md_inet_address logical) {
    struct sockaddr_storage address; socklen_t length;
    if (!md_loopback_address(f,inode,logical,&address,&length))
        unlink(((struct sockaddr_un *)&address)->sun_path);
}
int md_loopback_source(const struct md_network_fabric *f,const struct sockaddr_storage *ss,socklen_t length,
        struct md_inet_address *out) {
    const struct sockaddr_un *un=(const void *)ss;
    size_t head=offsetof(struct sockaddr_un,sun_path);
    if (un->sun_family!=AF_UNIX || length<=head || length>sizeof(*un)
            || strnlen(un->sun_path,length-head)!=length-head-1) return -EINVAL;
    char prefix[40]; int n=snprintf(prefix,sizeof(prefix),"/proc/self/fd/%d/",f->loopback_directory-1);
    if (strncmp(un->sun_path,prefix,n)) return -EINVAL;
    const char *p=un->sun_path+n; size_t digits=strspn(p,"0123456789abcdef");
    if (!digits || digits>16 || p[digits]!='-') return -EINVAL;
    p+=digits+1; char *end; unsigned long port=strtoul(p,&end,10);
    if (end==p || *end!='-' || !port || port>UINT16_MAX) return -EINVAL;
    const char *ip=end+1;
    *out=(struct md_inet_address){.ip=md_ip_any(strchr(ip,':') ? AF_INET6 : AF_INET),.port=htons(port)};
    return inet_pton(out->ip.family,ip,out->ip.bytes)==1 ? 0 : -EINVAL;
}
