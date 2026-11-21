#define _GNU_SOURCE
#include "network_launch.h"
#include "network_internal.h"
#include "network_endpoint.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static _Thread_local int denied;
int __real_socket(int,int,int);
int __wrap_socket(int family,int type,int protocol) {
    if (denied && (family==AF_INET || family==AF_INET6)) { errno=denied; return -1; }
    return __real_socket(family,type,protocol);
}
static void local_pair(struct md_network_namespace *n,int family,int type) {
    struct md_identity user=md_identity_new(1000,1000);
    struct md_fd_object *server=NULL,*client=NULL,*accepted=NULL;
    int fd=-1,other=-1;
    assert(!md_network_endpoint_open(n,1000,family,type,0,&server,&fd));
    assert(!md_network_endpoint_open(n,1000,family,type,0,&client,&other));
    assert(md_network_endpoint_local_carrier(server) && md_network_endpoint_local_carrier(client));
    struct md_inet_address target={.ip=md_ip_loopback(family)};
    struct sockaddr_storage guest,native,source; socklen_t length,size;
    assert(!md_inet_encode(&target,family,&guest,&length));
    assert(!md_network_endpoint_bind(server,fd,&user,(void *)&guest,length));
    assert(!md_network_endpoint_name(server,fd,0,&guest,&length));
    if (type==SOCK_STREAM) assert(!md_network_endpoint_listen(server,fd,1));
    assert(!md_network_endpoint_autobind(client,other,&user,(void *)&guest,length,0));
    assert(!md_network_endpoint_destination(client,(void *)&guest,length,&native,&size));
    assert(native.ss_family==AF_UNIX && !connect(other,(void *)&native,size));
    assert(!md_network_endpoint_connected(client,other,(void *)&guest,length));
    assert(write(other,"x",1)==1);
    struct sockaddr_storage name; socklen_t namesize;
    assert(!md_network_endpoint_name(client,other,0,&name,&namesize));
    struct md_inet_address from,reported;
    assert(!md_inet_decode((void *)&name,namesize,&from));
    char byte=0;
    if (type==SOCK_STREAM) {
        int connection=accept(fd,NULL,NULL); assert(connection>=0);
        assert(!md_network_endpoint_accept(server,connection,&accepted));
        assert(!md_network_endpoint_name(accepted,connection,1,&source,&size));
        assert(read(connection,&byte,1)==1);
        close(connection); md_fd_object_release(accepted);
    } else {
        /* The datagram must retain its source after the sender is gone. */
        close(other); other=-1; md_fd_object_release(client); client=NULL;
        size=sizeof(source);
        assert(recvfrom(fd,&byte,1,0,(void *)&source,&size)==1);
        assert(!md_network_endpoint_source(server,&source,&size));
    }
    assert(byte=='x' && !md_inet_decode((void *)&source,size,&reported) && md_inet_equal(&from,&reported));
    assert(!md_network_profile_ip(family==AF_INET ? "192.0.2.1" : "2001:db8::1",&target.ip));
    assert(!md_inet_encode(&target,family,&guest,&length));
    assert(md_network_endpoint_destination(server,(void *)&guest,length,&native,&size)==-ENETUNREACH);
    if (other>=0) { close(other); md_fd_object_release(client); }
    close(fd); md_fd_object_release(server); md_identity_release(&user);
}
void test_network_loopback(void) {
    const char *base=getenv("TMPDIR"); char path[PATH_MAX],child[PATH_MAX];
    assert(snprintf(path,sizeof(path),"%s/shroot-net-XXXXXX",base && *base ? base : "/tmp")<(int)sizeof(path));
    assert(mkdtemp(path));
    struct md_network_profile p={.policy=MD_NETWORK_NONE};
    struct md_network_launch launch={.temporary_parent=path}; assert(!md_network_launch_open(&p,NULL,&launch));
    struct md_fd_object *o=NULL; int fd=-1;
    assert(!md_network_endpoint_open(launch.space,0,AF_INET,SOCK_STREAM,0,&o,&fd));
    assert(!md_network_endpoint_local_carrier(o) && !launch.space->fabric->loopback_directory);
    close(fd); md_fd_object_release(o);
    denied=EMFILE;
    assert(md_network_endpoint_open(launch.space,0,AF_INET,SOCK_STREAM,0,&o,&fd)==-EMFILE);
    for (unsigned family=0;family<2;++family) {
        denied=family ? EACCES : EPERM;
        for (unsigned i=0;i<2;++i) local_pair(launch.space,family ? AF_INET6 : AF_INET,i ? SOCK_STREAM : SOCK_DGRAM);
    }
    md_network_launch_close(&launch);
    p.policy=MD_NETWORK_BRIDGE; launch.temporary_parent=path;
    assert(!md_network_launch_open(&p,NULL,&launch));
    assert(md_network_endpoint_open(launch.space,0,AF_INET,SOCK_STREAM,0,&o,&fd)==-EACCES);
    denied=0; md_network_launch_close(&launch);
    assert(snprintf(child,sizeof(child),"%s/.shroot-loopback-%u",path,(unsigned)getuid())<(int)sizeof(child));
    assert(!rmdir(child) && !rmdir(path));
    puts("PASS private TCP/UDP loopback after IP denial, native success, bridge denial and final cleanup");
}
