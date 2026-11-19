#define _GNU_SOURCE
#include "namespace_broker.h"
#include "cooperative_channel.h"
#include "cooperative_exchange.h"
#include "inode_store.h"
#include "svc_registry.h"
#include "task_registry.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>

static _Thread_local int fail_growth;
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *p,size_t size) {
    if (fail_growth) { fail_growth=0; errno=ENOMEM; return NULL; }
    return __real_realloc(p,size);
}

static void registration_failure(struct md_namespace_broker *b) {
    /* 1 and 258 share an index bucket. Reusing an unpublished record for 2
     * must not unlink the original task or make a failed update visible. */
    struct md_svc_code_pool pool={.address=4096};
    struct md_svc_registry image={.pools=&pool,.pool_count=1,.image=1};
    struct md_entry_channel channel;
    assert(!md_broker_task(b,1,MD_BROKER_COOPERATIVE,0,0,NULL,0));
    assert(!md_broker_cooperative_bind(b,1,&channel,1));
    fail_growth=1;
    assert(md_broker_task(b,1,0,0,0,&image,0)==-ENOMEM && !fail_growth);
    assert(atomic_load(&channel.enabled));
    fail_growth=1;
    assert(md_broker_task(b,258,0,0,0,&image,0)==-ENOMEM && !fail_growth);
    assert(md_broker_cooperative_bind(b,258,&channel,1)==-ESRCH);
    assert(!md_broker_task(b,2,0,0,0,NULL,0));
    assert(md_broker_cooperative_bind(b,1,&channel,1)==-EALREADY);
    assert(!md_broker_task(b,258,0,0,0,&image,0));
    md_broker_forget(b,258); md_broker_forget(b,2); md_broker_forget(b,1);
    assert(atomic_load(&channel.state)==MD_ENTRY_CLOSED);
}

enum forget_phase { BEFORE_DISPATCH, BEFORE_TAKE, AFTER_TAKE };
static struct {
    struct md_namespace_broker *broker;
    struct md_entry_channel *first;
    int status,hold_first;
} scenario;

static void publish(struct md_entry_channel *c,uint64_t sequence) {
    c->sequence=sequence; c->call.reserved=MD_ENTRY_BUFFER_CONTROL;
    md_entry_publish_request(c,MD_ENTRY_REQUEST);
    md_broker_entry_wake(scenario.broker,c->owner);
}
static void hold(pid_t pid) {
    struct rusage usage={.ru_minflt=17};
    assert(md_broker_hold_event(scenario.broker,pid,scenario.status,&usage)==1);
}
static void control(pid_t pid,struct md_entry_channel *c) {
    struct md_namespace_broker *b=scenario.broker;
    assert(md_broker_task_active(b,pid));
    if (c!=scenario.first) { md_broker_entry_reply(b,c,MD_ENTRY_COMPLETED,73); return; }
    if (scenario.hold_first) hold(pid);
    md_broker_entry_reply(b,c,MD_ENTRY_COMPLETED,51);
    assert(atomic_load(&c->state)==MD_ENTRY_RESPONSE && c->receipt==1 && c->result==51);
    publish(c,2);
    if (!scenario.hold_first) hold(pid);
    int status=0;
    assert(md_broker_task_active(b,pid) && md_broker_pending_events(b));
    assert(!md_broker_take_event(b,&status,NULL));
}
static void exchange(struct md_fs_worker *w,pid_t pid,int status,int hold_first,enum forget_phase phase) {
    struct md_namespace_broker *b=scenario.broker;
    struct md_entry_channel old,fresh;
    scenario.first=&old; scenario.status=status; scenario.hold_first=hold_first;
    assert(!md_broker_task(b,pid,MD_BROKER_COOPERATIVE,0,0,NULL,0));
    assert(!md_broker_cooperative_bind(b,pid,&old,1));
    publish(&old,1);
    assert(md_broker_entry_progress(b) && !md_broker_task_active(b,pid));
    assert(md_broker_pending_events(b) && !md_broker_entry_progress(b));
    assert(atomic_load(&old.state)==MD_ENTRY_REQUEST && old.receipt==1);
    if (phase!=BEFORE_DISPATCH) assert(!md_fs_worker_dispatch(w));
    int observed=-1;
    struct rusage usage={.ru_minflt=-1};
    if (phase==AFTER_TAKE) {
        assert(md_broker_take_event(b,&observed,&usage)==pid);
        assert(observed==status && usage.ru_minflt==17);
    }
    md_broker_forget(b,pid);
    assert(atomic_load(&old.state)==MD_ENTRY_CLOSED);
    assert(!md_broker_task(b,pid,MD_BROKER_COOPERATIVE,0,0,NULL,0));
    assert(!md_broker_cooperative_bind(b,pid,&fresh,1));
    publish(&fresh,1);
    assert(md_broker_entry_progress(b));
    assert(atomic_load(&fresh.state)==MD_ENTRY_RESPONSE && fresh.receipt==1 && fresh.result==73);
    if (phase==BEFORE_DISPATCH) assert(!md_fs_worker_dispatch(w));
    observed=-1; usage.ru_minflt=-1;
    assert(!md_broker_take_event(b,&observed,&usage) && !md_broker_pending_events(b));
    assert(observed==-1 && usage.ru_minflt==-1);
    md_broker_forget(b,pid);
    scenario.first=NULL;
}
void md_test_broker_identity(const char *store) {
    struct md_inode_store *inodes=NULL;
    assert(!md_inode_store_open(store,1,&inodes)); md_inode_store_close(inodes);
    struct md_task_registry *tasks=md_task_registry_create(); assert(tasks);
    struct md_fs_worker *worker=NULL;
    char endpoint[80]; snprintf(endpoint,sizeof(endpoint),"md-broker-identity-%d",getpid());
    assert(!md_fs_worker_start(store,endpoint,NULL,tasks,NULL,NULL,&worker));
    struct md_namespace_broker *b=md_broker_create(worker,0,NULL); assert(b);
    registration_failure(b);
    scenario.broker=b; md_broker_entry_handler(b,control);
    const int statuses[]={(SIGUSR1<<8)|0x7f,(PTRACE_EVENT_EXEC<<16)|(SIGTRAP<<8)|0x7f,
        (PTRACE_EVENT_EXIT<<16)|(SIGTRAP<<8)|0x7f,SIGKILL};
    for (size_t i=0;i<sizeof(statuses)/sizeof(*statuses);++i)
        for (int early=0;early<=1;++early)
            for (enum forget_phase p=BEFORE_DISPATCH;p<=AFTER_TAKE;++p)
                exchange(worker,getpid(),statuses[i],early,p);
    assert(!md_fs_worker_stop(worker)); md_broker_destroy(b);
    md_task_registry_destroy(tasks);
    puts("PASS broker identity: failed registration, held ownership and PID reuse in 24 schedules");
}
