#define _GNU_SOURCE
#include "fifo_readiness.h"
#include "network_connection.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned inject_after;
static int injected_error;
static uint32_t injected_events;
int __real_epoll_wait(int,struct epoll_event *,int,int);
int __wrap_epoll_wait(int fd,struct epoll_event *events,int capacity,int timeout) {
    if (!inject_after || --inject_after) return __real_epoll_wait(fd,events,capacity,timeout);
    assert(capacity>0 && timeout==0);
    if (injected_error) { errno=injected_error; return -1; }
    events[0]=(struct epoll_event){.events=injected_events};
    return injected_events ? 1 : 0;
}
static long poll_value(struct md_control_file f) { return f.ops->poll(f.context); }
static void errors(struct md_control_file f,unsigned stages) {
    const int codes[]={EINTR,EBADF,EINVAL};
    for (unsigned i=0;i<sizeof(codes)/sizeof(*codes);++i)
        for (unsigned stage=1;stage<=stages;++stage) {
            inject_after=stage; injected_error=codes[i];
            assert(poll_value(f)==-codes[i] && !inject_after);
        }
    injected_error=0;
}
static void connection(void) {
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,sockets));
    struct md_network_connection *c=md_network_connection_new(sockets[0]); assert(c);
    struct md_control_file f=md_network_connection_readiness(c),subscription={0};
    assert(!f.ops->poll_subscribe(f.context,sockets[0],EPOLLOUT,&subscription));
    for (unsigned state=0;state<2;++state) {
        if (state) {
            assert(!md_network_connection_begin(c));
            inject_after=1; injected_error=EINTR;
            assert(!poll_value(f) && inject_after==1);
            inject_after=0; injected_error=0;
            md_network_connection_complete(c,0);
        }
        errors(f,1); errors(subscription,2);
        injected_events=UINT32_C(0x80000000); inject_after=1;
        assert(poll_value(f)==(long)injected_events && !inject_after);
        injected_events=0; inject_after=1;
        assert(!poll_value(f) && !inject_after);
        assert(poll_value(f)&EPOLLOUT);
    }
    md_network_connection_reset(c);
    assert(!md_network_connection_begin(c));
    md_network_connection_complete(c,-ECONNREFUSED);
    inject_after=1; injected_error=EINTR;
    assert((poll_value(f)&(EPOLLERR|EPOLLHUP))==(EPOLLERR|EPOLLHUP) && inject_after==1);
    inject_after=0; injected_error=0;
    md_control_file_release(subscription); md_network_connection_free(c);
    close(sockets[0]); close(sockets[1]);
}
static void fifo(void) {
    int control=memfd_create("readiness-generations",MFD_CLOEXEC),pipefd[2];
    assert(control>=0 && !ftruncate(control,8) && !pipe2(pipefd,O_CLOEXEC|O_NONBLOCK));
    struct md_fifo_readiness *fifo=md_fifo_readiness_new(control,0); assert(fifo);
    assert(!md_fifo_readiness_attach(fifo,pipefd[0]));
    struct md_control_file f=md_fifo_readiness_control(fifo),subscription={0};
    assert(!f.ops->poll_subscribe(f.context,pipefd[0],EPOLLIN,&subscription));
    errors(f,2); errors(subscription,3);
    assert(!poll_value(f));
    assert(write(pipefd[1],"x",1)==1 && (poll_value(f)&EPOLLIN));
    md_control_file_release(subscription); md_fifo_readiness_free(fifo);
    close(pipefd[0]); close(pipefd[1]); close(control);
}
void test_control_readiness(void) {
    connection(); fifo();
    puts("PASS readiness errors: native/completed connect, pending/failure suppression, FIFO and observer propagation");
}
