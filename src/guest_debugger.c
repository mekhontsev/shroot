#define _GNU_SOURCE
#include "guest_debugger.h"
#include "pid_calls.h"
#include "task_pending.h"
#include "resource_abi.h"
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/audit.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

struct inferior {
    struct inferior *next,*indexed;
    struct inferior *ready_next,**ready_previous;
    /* The debugger and real parent consume separate exit events. Its admitted
     * visible number remains valid after the parent has reaped native state. */
    pid_t pid, owner, group, number, exec_former;
    uid_t uid;
    unsigned long options, message;
    uint64_t syscall_marker;
    int stopped, status, step, terminal, real_child;
    int seized, pending, syscall_mode, syscall_stop;
    struct ptrace_syscall_info syscall;
    struct rusage usage;
    siginfo_t info;
    struct md_signal_origin origin;
};
struct waiting {
    struct waiting *next;
    pid_t pid;
    struct seccomp_data call;
    pid_t *candidates;
    size_t candidate,count;
    int probing, retry, filtered, native_children;
};
enum { INFERIOR_BUCKETS=257 };
struct md_debugger {
    struct md_debugger_host host;
    struct inferior *inferiors;
    struct inferior *index[INFERIOR_BUCKETS];
    struct inferior *ready,**ready_tail;
    struct waiting *waiters;
};
static void ready_remove(struct md_debugger *d,struct inferior *p) {
    if (!p->ready_previous) return;
    *p->ready_previous=p->ready_next;
    if (p->ready_next) p->ready_next->ready_previous=p->ready_previous;
    else d->ready_tail=p->ready_previous;
    p->ready_next=NULL; p->ready_previous=NULL;
}
static void ready_append(struct md_debugger *d,struct inferior *p) {
    ready_remove(d,p);
    p->ready_previous=d->ready_tail;
    *d->ready_tail=p; d->ready_tail=&p->ready_next;
}
static void wait_free(struct waiting *w) { free(w->candidates); free(w); }
static struct inferior *find(struct md_debugger *d, pid_t pid) {
    for (struct inferior *p=d->index[(unsigned)pid%INFERIOR_BUCKETS]; p; p=p->indexed)
        if (p->pid==pid) return p;
    return NULL;
}
static void index_add(struct md_debugger *d,struct inferior *p) {
    unsigned bucket=(unsigned)p->pid%INFERIOR_BUCKETS;
    p->indexed=d->index[bucket]; d->index[bucket]=p;
}
static void index_remove(struct md_debugger *d,struct inferior *p) {
    struct inferior **at=&d->index[(unsigned)p->pid%INFERIOR_BUCKETS];
    while (*at!=p) at=&(*at)->indexed;
    *at=p->indexed; p->indexed=NULL;
}
static void unlink_inferior(struct md_debugger *d,struct inferior **at) {
    struct inferior *p=*at;
    ready_remove(d,p);
    *at=p->next; index_remove(d,p);
}
static int transfer(pid_t pid, uintptr_t address, void *bytes, size_t size, int write) {
    if (!size) return 0;
    if (!address || address>UINTPTR_MAX-size) return -EFAULT;
    struct iovec local={bytes,size}, remote={(void *)address,size};
    ssize_t n=write ? process_vm_writev(pid,&local,1,&remote,1,0) : process_vm_readv(pid,&local,1,&remote,1,0);
    return n==(ssize_t)size ? 0 : -EFAULT;
}
static long request(struct md_debugger *d,int op, pid_t pid, uintptr_t address, void *data) {
    errno=0;
    if (!d->host.trace) return -ENOSYS;
    long r=d->host.trace(op,pid,(void *)address,data);
    return r==-1 && errno ? -errno : r;
}
struct md_debugger *md_debugger_create(const struct md_debugger_host *host) {
    struct md_debugger *d=calloc(1,sizeof(*d));
    if (d) { d->host=*host; d->ready_tail=&d->ready; }
    return d;
}
void md_debugger_destroy(struct md_debugger *d) {
    if (!d) return;
    while (d->inferiors) { struct inferior *p=d->inferiors; unlink_inferior(d,&d->inferiors); free(p); }
    while (d->waiters) { struct waiting *p=d->waiters; d->waiters=p->next; wait_free(p); }
    free(d);
}
static int add(struct md_debugger *d, pid_t pid, pid_t owner, unsigned long options) {
    if (find(d,pid)) return -EPERM;
    struct inferior *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    *p=(struct inferior){.next=d->inferiors,.pid=pid,.owner=owner,.options=options,
        .number=d->host.visible_pid ? d->host.visible_pid(owner,pid) : pid,
        /* Nonleader threads have no native parent wait result. Their terminal
         * event belongs to this tracing relationship, even when the debugger
         * is also the thread group's real parent. */
        .real_child=d->host.group(pid)==pid
            && d->host.group(d->host.parent(pid))==d->host.group(owner),.group=getpgid(pid)};
    d->inferiors=p; index_add(d,p);
    int error=d->host.observe(owner);
    if (error) { unlink_inferior(d,&d->inferiors); free(p); }
    return error;
}
static pid_t visible(struct md_debugger *d,pid_t observer,pid_t native) {
    return d->host.visible_pid ? d->host.visible_pid(observer,native) : native;
}
static pid_t native(struct md_debugger *d,pid_t observer,pid_t number) {
    return d->host.native_pid ? d->host.native_pid(observer,number) : number;
}
static uid_t visible_uid(struct md_debugger *d,pid_t observer,pid_t sender,uid_t fallback) {
    return d->host.visible_uid ? d->host.visible_uid(observer,sender,fallback) : fallback;
}
static void signal_info_visible(struct md_debugger *d,pid_t observer,
        const struct md_signal_origin *origin,siginfo_t *info) {
    if (md_signal_origin_matches(origin,info) && d->host.signal_translate)
        d->host.signal_translate(observer,origin,info);
    else if (md_signal_native_sender(info)) {
        info->si_uid=visible_uid(d,observer,info->si_pid,info->si_uid);
        info->si_pid=visible(d,observer,info->si_pid);
    }
}
struct pending_peek {
    struct md_debugger *debugger;
    pid_t caller,target;
    uintptr_t output;
    uint64_t skip;
    int limit,copied;
};
static int pending_peek_copy(void *context,const siginfo_t *info) {
    struct pending_peek *p=context;
    if (p->skip) { --p->skip; return 0; }
    struct md_signal_origin origin={0};
    struct md_debugger *d=p->debugger;
    if (d->host.signal_origin) d->host.signal_origin(p->target,info,&origin,0);
    siginfo_t value=*info;
    signal_info_visible(d,p->caller,&origin,&value);
    int error=transfer(p->caller,p->output,&value,sizeof(value),1);
    if (error) return error;
    p->output+=sizeof(value);
    return ++p->copied==p->limit;
}
static int selected(struct md_debugger *d,pid_t owner, const struct seccomp_data *call, const struct inferior *p) {
    pid_t pid=p->number;
    if (!pid) return 0;
    if (call->nr==SYS_waitid) {
        if (call->args[0]==P_ALL) return 1;
        if (call->args[0]==P_PID) return call->args[1]==(unsigned)pid;
        return call->args[0]==P_PGID && (call->args[1] ? visible(d,owner,p->group)==(pid_t)call->args[1] : p->group==getpgid(owner));
    }
    pid_t wanted=(pid_t)call->args[0];
    return wanted==-1 || wanted==pid || (!wanted && p->group==getpgid(owner))
        || (wanted < -1 && (int64_t)visible(d,owner,p->group)==-(int64_t)wanted);
}
static unsigned wait_options(const struct seccomp_data *call) {
    return (unsigned)call->args[call->nr==SYS_waitid ? 3 : 2];
}
static int wait_children(struct md_debugger *d,pid_t owner,const struct seccomp_data *call,
        pid_t **candidates,size_t *count,int *live) {
    *live=0;
    int filtered=d->host.wait_children ? d->host.wait_children(owner,call,candidates,count) : 0;
    if (filtered<=0 || !*count || !d->inferiors || (wait_options(call)&(WCONTINUED|__WNOTHREAD))) return filtered;
    pid_t group=d->host.group(owner);
    size_t kept=0;
    for (size_t i=0;i<*count;++i) {
        struct inferior *p=find(d,native(d,owner,(*candidates)[i]));
        /* Live tracees publish stops here, not in the real parent's queue.
         * Their exit removes/transitions this record before native reaping.
         * Private-child exclusion must not re-probe every sleeping tracee. */
        int owned=p && (p->owner==owner || d->host.group(p->owner)==group);
        if (p && !p->terminal && (owned || !(wait_options(call)&WUNTRACED))) {
            if (!owned) *live=1;
            continue;
        }
        (*candidates)[kept++]=(*candidates)[i];
    }
    *count=kept;
    return filtered;
}
static int wait_info(pid_t owner,uintptr_t address,const siginfo_t *info) {
    if (!address) return 0;
    if (address>UINTPTR_MAX-sizeof(*info)) return -EFAULT;
    /* waitid writes these fields only, leaving padding, times and rusage
     * unchanged when no event is ready. Publish them with one memory copy. */
#define FIELD(name) {offsetof(siginfo_t,name),sizeof(info->name)}
    static const struct { size_t offset,size; } fields[]={
        FIELD(si_signo),FIELD(si_errno),FIELD(si_code),FIELD(si_pid),FIELD(si_uid),FIELD(si_status)};
#undef FIELD
    enum { COUNT=sizeof(fields)/sizeof(*fields) };
    struct iovec local[COUNT],remote[COUNT];
    size_t size=0;
    for (unsigned i=0;i<COUNT;++i) {
        local[i]=(struct iovec){(char *)info+fields[i].offset,fields[i].size};
        remote[i]=(struct iovec){(void *)(address+fields[i].offset),fields[i].size};
        size+=fields[i].size;
    }
    return process_vm_writev(owner,local,COUNT,remote,COUNT,0)==(ssize_t)size ? 0 : -EFAULT;
}
static void wait_empty(struct md_debugger *d,pid_t owner,const struct seccomp_data *call,long value) {
    if (!value && call->nr==SYS_waitid) value=wait_info(owner,call->args[2],&(siginfo_t){0});
    d->host.complete(owner,value);
}
static int wait_result(struct md_debugger *d, pid_t owner,const struct seccomp_data *call,int *children) {
    struct inferior *chosen=NULL,*exact=NULL;
    *children=0;
    int id=call->nr==SYS_waitid;
    int directed=id ? call->args[0]==P_PID : (pid_t)call->args[0]>0;
    struct inferior *first=d->inferiors;
    if (directed && first) {
        pid_t number=(pid_t)call->args[id ? 1 : 0];
        struct inferior *indexed=find(d,native(d,owner,number));
        /* A real parent may already have retired the namespace entry while
         * the debugger still owns its terminal event and visible number. */
        if (indexed && indexed->number==number) first=indexed;
    }
    pid_t group=d->inferiors ? d->host.group(owner) : 0;
    /* Publication order belongs to the event queue, not to the complete task
     * population. Sleeping inferiors need no visit when an event is ready. */
    if (!directed) for (struct inferior *p=d->ready;p;p=p->ready_next) {
        if ((p->owner!=owner && d->host.group(p->owner)!=group) || !selected(d,owner,call,p)) continue;
        if (!id || (wait_options(call)&(p->terminal ? WEXITED : WSTOPPED))) {
            chosen=p; *children=1; break;
        }
    }
    for (struct inferior *p=chosen ? NULL : first; p; p=p->next) {
        if ((p->owner!=owner && d->host.group(p->owner)!=group) || !selected(d,owner,call,p)) continue;
        *children=1;
        if (directed) {
            exact=p;
            if (p->ready_previous && (!id || (wait_options(call)&(p->terminal ? WEXITED : WSTOPPED)))) chosen=p;
        }
        break;
    }
    if (!chosen) {
        /* This exact live inferior's stops belong to this owner. Its terminal
         * event removes/transitions the record before real-parent reaping;
         * no native child can contribute a different result for this PID. */
        if (exact && !exact->terminal && (wait_options(call)&WNOHANG)
                && !(wait_options(call)&(WCONTINUED|__WNOTHREAD))) {
            int error=id ? wait_info(owner,call->args[2],&(siginfo_t){0}) : 0;
            d->host.complete(owner,error); return 1;
        }
        return 0;
    }
    long value=chosen->number;
    int error;
    uintptr_t usage;
    if (call->nr==SYS_waitid) {
        siginfo_t info={.si_signo=SIGCHLD,.si_pid=(pid_t)value,
            .si_uid=visible_uid(d,owner,chosen->pid,chosen->uid)};
        info.si_code=chosen->terminal ? (WIFEXITED(chosen->status) ? CLD_EXITED
            : WCOREDUMP(chosen->status) ? CLD_DUMPED : CLD_KILLED) : CLD_TRAPPED;
        info.si_status=chosen->terminal ? (WIFEXITED(chosen->status) ? WEXITSTATUS(chosen->status)
            : WTERMSIG(chosen->status)) : (chosen->status>>8);
        error=wait_info(owner,call->args[2],&info);
        usage=call->args[4]; value=0;
    } else {
        error=call->args[1] ? transfer(owner,call->args[1],&chosen->status,sizeof(int),1) : 0;
        usage=call->args[3];
    }
    if (!error && usage) {
        struct md_rusage result=md_rusage_kernel(&chosen->usage);
        error=transfer(owner,usage,&result,sizeof(result),1);
    }
    if (!error && !(call->nr==SYS_waitid && (wait_options(call)&WNOWAIT))) {
        ready_remove(d,chosen);
        if (chosen->terminal) {
            struct inferior **at=&d->inferiors;
            while (*at!=chosen) at=&(*at)->next;
            unlink_inferior(d,at);
            if (d->host.reaped) d->host.reaped(owner,chosen->pid,0);
            free(chosen);
        }
    }
    d->host.complete(owner,error ? error : value);
    return 1;
}
static int wake_waiters(struct md_debugger *d,pid_t owner) {
    int waiting=0;
    for (struct waiting *w=d->waiters,*next; w; w=next) {
        next=w->next;
        if (d->host.group(w->pid)==d->host.group(owner)) {
            waiting=1;
            if (w->probing) w->retry=1;
            else d->host.wait_wake(w->pid);
        }
    }
    return waiting;
}
static void wake(struct md_debugger *d, pid_t owner) {
    /* The debugger may use a SIGCHLD self-pipe instead of a blocking wait. */
    if (!wake_waiters(d,owner)) kill(owner,SIGCHLD);
}
void md_debugger_child_changed(struct md_debugger *d,pid_t pid) {
    if (!d || !d->waiters) return;
    pid_t parent=d->host.parent(pid);
    if (parent>0) wake_waiters(d,parent);
}
int md_debugger_stop(struct md_debugger *d, pid_t pid, int status, const siginfo_t *info, unsigned long message) {
    struct inferior *p=find(d,pid);
    if (!p) return 0;
    /* Any published ptrace stop satisfies INTERRUPT, including a syscall
     * exit racing its delivery. Internal runtime stops never reach here. */
    p->pending=0;
    p->stopped=1; p->status=status; p->message=message; p->step=0;
    p->uid=d->host.uid(pid);
    d->host.usage(pid,&p->usage);
    p->syscall.op=PTRACE_SYSCALL_INFO_NONE;
    p->syscall_stop=0;
    p->info=info ? *info : (siginfo_t){.si_signo=WSTOPSIG(status),
        .si_code=(unsigned)status>>16 ? status>>8 : SI_KERNEL,.si_pid=pid};
    struct md_signal_origin origin={0};
    p->origin.valid=0;
    if (d->host.signal_origin) d->host.signal_origin(pid,&p->info,&origin,1);
    p->origin=origin;
    ready_append(d,p);
    wake(d,p->owner);
    return 1;
}
int md_debugger_exec(struct md_debugger *d, pid_t pid, pid_t former) {
    struct inferior *p=find(d,pid);
    if (!p) return 0;
    unsigned event=p->options & PTRACE_O_TRACEEXEC ? PTRACE_EVENT_EXEC : 0;
    if (!event && p->seized) return 0;
    pid_t message=p->exec_former ? p->exec_former : visible(d,p->owner,former);
    p->exec_former=0;
    return md_debugger_stop(d,pid,(SIGTRAP<<8)|0x7f|(event<<16),NULL,(unsigned long)message);
}
int md_debugger_event(struct md_debugger *d, pid_t pid, unsigned event, unsigned long message) {
    struct inferior *p=find(d,pid);
    if (!p || !(p->options&(1UL<<event))) return 0;
    return md_debugger_stop(d,pid,(SIGTRAP<<8)|0x7f|(event<<16),NULL,message);
}
int md_debugger_seccomp(struct md_debugger *d,pid_t pid,const struct seccomp_data *call,
        uintptr_t stack,unsigned data) {
    if (!d->host.seccomp_events || !md_debugger_event(d,pid,PTRACE_EVENT_SECCOMP,data)) return 0;
    struct inferior *p=find(d,pid);
    p->syscall=(struct ptrace_syscall_info){.op=PTRACE_SYSCALL_INFO_SECCOMP,
        .arch=call->arch,.instruction_pointer=call->instruction_pointer,.stack_pointer=stack};
    p->syscall.seccomp.nr=call->nr;
    p->syscall.seccomp.ret_data=data;
    memcpy(p->syscall.seccomp.args,call->args,sizeof(p->syscall.seccomp.args));
    return 1;
}
int md_debugger_birth(struct md_debugger *d, pid_t parent, pid_t child, unsigned event) {
    struct inferior *p=find(d,parent);
    if (!p || !(p->options & (1UL<<event))) return 0;
    int error=add(d,child,p->owner,p->options);
    if (error) return error;
    find(d,child)->seized=p->seized;
    return md_debugger_stop(d,parent,(SIGTRAP<<8)|0x7f|(event<<16),NULL,(unsigned long)child);
}
int md_debugger_step(struct md_debugger *d, pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && p->step;
}
int md_debugger_traced(struct md_debugger *d, pid_t pid) {
    struct inferior *p=d ? find(d,pid) : NULL;
    return p && !p->terminal;
}
pid_t md_debugger_owner(struct md_debugger *d,pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && !p->terminal ? p->owner : 0;
}
int md_debugger_stopped_by(struct md_debugger *d,pid_t target,pid_t owner) {
    struct inferior *p=d ? find(d,target) : NULL;
    return p && p->owner==owner && p->stopped && !p->terminal && !p->pending;
}
int md_debugger_running(struct md_debugger *d,pid_t target) {
    struct inferior *p=d ? find(d,target) : NULL;
    return p && !p->terminal && !p->stopped && !p->pending;
}
int md_debugger_stop_pending(struct md_debugger *d,pid_t pid) {
    struct inferior *p=d ? find(d,pid) : NULL;
    return p && !p->terminal && !p->stopped && p->pending;
}
int md_debugger_active(struct md_debugger *d) { return d->inferiors!=NULL || d->waiters!=NULL; }
int md_debugger_newborn(struct md_debugger *d, pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && md_debugger_stop(d,pid,p->seized ? (SIGTRAP<<8)|0x7f|(PTRACE_EVENT_STOP<<16)
        : (SIGSTOP<<8)|0x7f,NULL,0);
}
int md_debugger_boundary(struct md_debugger *d, pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && !p->stopped && p->pending ? md_debugger_newborn(d,pid) : 0;
}
int md_debugger_syscall_mode(struct md_debugger *d, pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && p->syscall_mode;
}
int md_debugger_syscall_emulated(struct md_debugger *d,pid_t pid) {
    struct inferior *p=find(d,pid);
    return p && p->syscall_mode==PTRACE_SYSEMU;
}
int md_debugger_syscall_entry(struct md_debugger *d,pid_t pid,struct seccomp_data *call) {
    struct inferior *p=find(d,pid);
    if (!p || (p->syscall_stop!=1 && p->syscall.op!=PTRACE_SYSCALL_INFO_SECCOMP)) return 0;
    *call=(struct seccomp_data){.nr=(int)p->syscall.entry.nr,.arch=p->syscall.arch,
        .instruction_pointer=p->syscall.instruction_pointer};
    memcpy(call->args,p->syscall.entry.args,sizeof(call->args));
    return 1;
}
int md_debugger_syscall_observed(struct md_debugger *d,pid_t pid,const struct ptrace_syscall_info *info) {
    int entry=info->op==PTRACE_SYSCALL_INFO_ENTRY;
    if (!entry && info->op!=PTRACE_SYSCALL_INFO_EXIT) return 0;
    struct inferior *p=find(d,pid);
    if (!p || !p->syscall_mode || (!entry && p->syscall_mode==PTRACE_SYSEMU)) return 0;
    int stopped=md_debugger_stop(d,pid,((SIGTRAP|(p->options&PTRACE_O_TRACESYSGOOD ? 0x80 : 0))<<8)|0x7f,NULL,0);
    p->syscall_stop=entry ? 1 : 2;
    p->syscall_marker=entry ? 0 : 1;
    p->syscall=*info;
    if (!(p->options&PTRACE_O_TRACESYSGOOD)) p->syscall.op=PTRACE_SYSCALL_INFO_NONE;
    return stopped;
}
void md_debugger_exit(struct md_debugger *d, pid_t pid, int status) {
    if (!md_debugger_active(d)) return;
    struct inferior *ending=find(d,pid);
    pid_t parent=d->host.parent(pid);
    pid_t notify=0;
    if (ending && !ending->real_child) {
        ending->terminal=1; ending->status=status; ending->stopped=0;
        ending->uid=d->host.uid(pid);
        d->host.usage(pid,&ending->usage);
        ready_append(d,ending); notify=ending->owner;
    }
    struct inferior **at=&d->inferiors;
    pid_t owner=0;
    while (*at) {
        struct inferior *p=*at;
        if ((p->pid==pid && !p->terminal) || p->owner==pid) {
            unlink_inferior(d,at);
            if (p->pid==pid) owner=p->owner;
            else if (!p->terminal) {
                if (p->options & PTRACE_O_EXITKILL) kill(p->pid,SIGKILL);
                /* The real ptracer survives the guest tracer. Release its
                 * stop even after EXITKILL: an exit-event stop cannot die
                 * until its ptracer resumes it. */
                d->host.options(p->pid,0);
                if (p->stopped) d->host.resume(p->pid,0,&p->origin,0);
            }
            if (p->terminal && d->host.reaped) d->host.reaped(pid,p->pid,0);
            free(p);
        } else at=&p->next;
    }
    struct waiting **waiting=&d->waiters;
    while (*waiting) {
        struct waiting *w=*waiting;
        if (w->pid==pid) {
            *waiting=w->next;
            wait_free(w);
        } else waiting=&w->next;
    }
    if (notify) wake(d,notify);
    /* Real children already publish a kernel SIGCHLD, respecting SIG_IGN and
     * SA_NOCLDWAIT. Only the synthetic tracer relationship needs a notice. */
    if (owner) wake_waiters(d,owner);
    if (parent && parent!=owner && parent!=notify) wake_waiters(d,parent);
}
void md_debugger_rekey(struct md_debugger *d, pid_t old, pid_t pid) {
    struct inferior *source=find(d,old);
    struct inferior **at=&d->inferiors;
    while (*at) {
        struct inferior *p=*at;
        if (p->pid==pid && source && p!=source) { unlink_inferior(d,at); free(p); continue; }
        if (p->pid==old) {
            p->exec_former=visible(d,p->owner,old);
            p->number=visible(d,p->owner,pid);
            index_remove(d,p); p->pid=pid; index_add(d,p);
            p->real_child=d->host.group(d->host.parent(pid))==d->host.group(p->owner);
        }
        if (p->owner==old) p->owner=pid;
        at=&p->next;
    }
    struct waiting **w=&d->waiters;
    while (*w) {
        if ((*w)->pid==old) { struct waiting *gone=*w; *w=gone->next; wait_free(gone); }
        else w=&(*w)->next;
    }
}
static unsigned long supported_options(const struct md_debugger *d) {
    return PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE
        |PTRACE_O_TRACEEXEC|PTRACE_O_TRACEVFORKDONE|PTRACE_O_TRACEEXIT|PTRACE_O_EXITKILL
        |(d->host.seccomp_events ? PTRACE_O_TRACESECCOMP : 0);
}
static void syscall_registers_changed(struct inferior *p,uintptr_t note,const void *bytes,size_t size) {
    struct ptrace_syscall_info *info=&p->syscall;
    int entry=info->op==PTRACE_SYSCALL_INFO_ENTRY || info->op==PTRACE_SYSCALL_INFO_SECCOMP;
    if (note==NT_ARM_SYSTEM_CALL && size>=sizeof(int) && entry) {
        int number; memcpy(&number,bytes,sizeof(number));
        info->entry.nr=(uint64_t)(int64_t)number;
    } else if (note==NT_PRSTATUS && info->op!=PTRACE_SYSCALL_INFO_NONE) {
        /* orig_x0 and the latched syscall number are independent of x0/x8.
         * Other fields reflect successful regset writes, including prefixes. */
        if (size>=offsetof(struct user_pt_regs,pc)+sizeof(uint64_t))
            memcpy(&info->instruction_pointer,(const char *)bytes+offsetof(struct user_pt_regs,pc),sizeof(uint64_t));
        if (size>=offsetof(struct user_pt_regs,sp)+sizeof(uint64_t))
            memcpy(&info->stack_pointer,(const char *)bytes+offsetof(struct user_pt_regs,sp),sizeof(uint64_t));
        if (entry) {
            for (unsigned i=1;i<6;++i) if (size>=(i+1)*sizeof(uint64_t))
                memcpy(&info->entry.args[i],(const char *)bytes+i*sizeof(uint64_t),sizeof(uint64_t));
        } else if (info->op==PTRACE_SYSCALL_INFO_EXIT && size>=sizeof(uint64_t)) {
            memcpy(&info->exit.rval,bytes,sizeof(uint64_t));
            info->exit.is_error=(uint64_t)info->exit.rval>=(uint64_t)-4095;
        }
    }
}
static long regset(struct md_debugger *d,pid_t caller, struct inferior *p, int op, uintptr_t note, uintptr_t address) {
    struct iovec guest;
    int r=transfer(caller,address,&guest,sizeof(guest),0);
    if (r) return r;
    if (guest.iov_len>65536) return -E2BIG;
    void *bytes=calloc(1,guest.iov_len ? guest.iov_len : 1);
    if (!bytes) return -ENOMEM;
    struct iovec local={bytes,guest.iov_len};
    if (op==PTRACE_SETREGSET) r=transfer(caller,(uintptr_t)guest.iov_base,bytes,guest.iov_len,0);
    size_t marker=offsetof(struct user_pt_regs,regs[7]);
    int syscall_registers=note==NT_PRSTATUS && p->syscall_stop && local.iov_len>=marker+sizeof(uint64_t);
    /* ARM64 saves the application x7 across a syscall stop. Regset writes
     * change the visible marker until resume, not that saved application x7. */
    uint64_t written_marker=0;
    if (!r && syscall_registers && op==PTRACE_SETREGSET) {
        memcpy(&written_marker,(char *)bytes+marker,sizeof(written_marker));
        struct user_pt_regs current;
        struct iovec saved={&current,sizeof(current)};
        r=(int)request(d,PTRACE_GETREGSET,p->pid,NT_PRSTATUS,&saved);
        if (!r) memcpy((char *)bytes+marker,&current.regs[7],sizeof(uint64_t));
    }
    if (!r) r=(int)request(d,op,p->pid,note,&local);
    if (!r && op==PTRACE_SETREGSET) syscall_registers_changed(p,note,bytes,local.iov_len);
    if (!r && syscall_registers && op==PTRACE_SETREGSET
            && local.iov_len>=marker+sizeof(uint64_t)) p->syscall_marker=written_marker;
    if (!r && syscall_registers && op==PTRACE_GETREGSET) {
        memcpy((char *)bytes+marker,&p->syscall_marker,sizeof(p->syscall_marker));
    }
    if (!r && op==PTRACE_GETREGSET) r=transfer(caller,(uintptr_t)guest.iov_base,bytes,local.iov_len,1);
    guest.iov_len=local.iov_len;
    if (!r) r=transfer(caller,address,&guest,sizeof(guest),1);
    free(bytes); return r;
}
static long control(struct md_debugger *d, pid_t caller, const struct seccomp_data *call) {
    int op=(int)call->args[0]; pid_t pid=native(d,caller,(pid_t)call->args[1]);
    uintptr_t address=call->args[2], data=call->args[3];
    if (op==PTRACE_TRACEME) {
        pid_t parent=d->host.parent(caller);
        return parent>0 && d->host.traceme(parent,caller) ? add(d,caller,parent,0) : -EPERM;
    }
    if (op==PTRACE_ATTACH || op==PTRACE_SEIZE) {
        if (op==PTRACE_SEIZE && (address || (data&~supported_options(d)))) return -EIO;
        if (!d->host.attachable(caller,pid)) return -EPERM;
        int error=add(d,pid,caller,op==PTRACE_SEIZE ? data : 0);
        if (error) return error;
        struct inferior *target=find(d,pid);
        target->seized=op==PTRACE_SEIZE;
        error=d->host.options(pid,target->options);
        if (!error && op==PTRACE_ATTACH) {
            target->pending=1; error=d->host.interrupt(pid);
        }
        if (error) {
            unlink_inferior(d,&d->inferiors); free(target);
            d->host.options(pid,0);
        }
        return error;
    }
    struct inferior *p=find(d,pid);
    /* Admission establishes the relationship. A later UID/GID or domain
     * change does not revoke continuation or detach; memory access is separate. */
    if (!p || p->terminal || p->owner!=caller) return -ESRCH;
    if (op==PTRACE_INTERRUPT) {
        if (!p->seized) return -EIO;
        int previous=p->pending;
        p->pending=1;
        int error=p->stopped ? 0 : d->host.interrupt(pid);
        if (error) p->pending=previous;
        return error;
    }
    if (op==PTRACE_KILL) return kill(pid,SIGKILL) ? -errno : 0;
    if (!p->stopped) return -ESRCH;
    switch (op) {
    case PTRACE_LISTEN: {
        if (!p->seized || (unsigned)p->status>>16!=PTRACE_EVENT_STOP) return -EIO;
        int error=d->host.listen(pid);
        if (!error) { p->stopped=0; ready_remove(d,p); }
        return error;
    }
    case PTRACE_SETOPTIONS: {
        if (data & ~supported_options(d)) return -EINVAL;
        int error=d->host.options(pid,data);
        if (!error) p->options=data;
        return error;
    }
    case PTRACE_GETEVENTMSG: {
        unsigned event=(unsigned)p->status>>16;
        unsigned long message=p->message;
        if (event==PTRACE_EVENT_FORK || event==PTRACE_EVENT_VFORK || event==PTRACE_EVENT_CLONE
                || event==PTRACE_EVENT_VFORK_DONE)
            message=(unsigned long)visible(d,caller,(pid_t)message);
        return transfer(caller,data,&message,sizeof(message),1);
    }
    case PTRACE_GETSIGINFO: {
        siginfo_t info=p->info;
        signal_info_visible(d,caller,&p->origin,&info);
        return transfer(caller,data,&info,sizeof(info),1);
    }
    case PTRACE_PEEKSIGINFO: {
        struct ptrace_peeksiginfo_args args;
        int error=transfer(caller,address,&args,sizeof(args),0);
        if (error) return error;
        if (args.nr<0 || (args.flags&~PTRACE_PEEKSIGINFO_SHARED)) return -EINVAL;
        if (!args.nr) return 0;
        if (!d->host.trace) return -ENOSYS;
        struct pending_peek copy={.debugger=d,.caller=caller,.target=pid,
            .output=data,.skip=args.off,.limit=args.nr};
        error=md_task_pending_scan_scope(d->host.trace,pid,args.flags,pending_peek_copy,&copy);
        return copy.copied ? copy.copied : error<0 ? error : 0;
    }
    case PTRACE_SETSIGINFO: {
        siginfo_t info;
        struct md_signal_origin origin={0};
        int error=transfer(caller,data,&info,sizeof(info),0);
        if (!error && md_signal_child_notice(&info) && md_signal_origin_matches(&p->origin,&p->info)
                && d->host.signal_translate) {
            siginfo_t visible=p->info;
            d->host.signal_translate(caller,&p->origin,&visible);
            if (info.si_pid==visible.si_pid && info.si_uid==visible.si_uid) {
                /* A reaped sender is no longer in the PID lookup table. */
                origin=p->origin;
                if (info.si_code!=visible.si_code || info.si_status!=visible.si_status)
                    origin.reboot_signal=0;
                info.si_pid=p->info.si_pid; info.si_uid=p->info.si_uid;
                origin.info=info;
            }
        }
        if (!error && !origin.valid && md_signal_native_sender(&info))
            info.si_pid=native(d,caller,info.si_pid);
        if (!error) error=(int)request(d,op,pid,0,&info);
        if (!error) {
            p->info=info;
            if (!origin.valid && d->host.signal_origin) d->host.signal_origin(pid,&info,&origin,1);
            p->origin=origin;
        }
        return error;
    }
    case PTRACE_GETREGSET: case PTRACE_SETREGSET: return regset(d,caller,p,op,address,data);
    case PTRACE_GET_SYSCALL_INFO: {
        struct ptrace_syscall_info info=p->syscall;
        if (info.op==PTRACE_SYSCALL_INFO_NONE) {
            struct user_pt_regs registers;
            struct iovec io={&registers,sizeof(registers)};
            int error=(int)request(d,PTRACE_GETREGSET,pid,NT_PRSTATUS,&io);
            if (error) return error;
            info.arch=AUDIT_ARCH_AARCH64;
            info.instruction_pointer=registers.pc; info.stack_pointer=registers.sp;
        }
        size_t size=offsetof(struct ptrace_syscall_info,entry);
        if (info.op==PTRACE_SYSCALL_INFO_ENTRY) size+=sizeof(info.entry);
        if (info.op==PTRACE_SYSCALL_INFO_EXIT) size=offsetof(struct ptrace_syscall_info,exit.is_error)+1;
        if (info.op==PTRACE_SYSCALL_INFO_SECCOMP) size=offsetof(struct ptrace_syscall_info,seccomp.ret_data)+sizeof(info.seccomp.ret_data);
        int error=transfer(caller,data,&info,address<size ? address : size,1);
        return error ? error : (long)size;
    }
    case PTRACE_GETSIGMASK: case PTRACE_SETSIGMASK: {
        uint64_t mask;
        if (address!=sizeof(mask)) return -EINVAL;
        int error=op==PTRACE_SETSIGMASK ? transfer(caller,data,&mask,sizeof(mask),0) : 0;
        if (!error) error=d->host.signal_mask ? d->host.signal_mask(pid,op==PTRACE_SETSIGMASK,&mask)
            : (int)request(d,op,pid,address,&mask);
        if (!error && op==PTRACE_GETSIGMASK) error=transfer(caller,data,&mask,sizeof(mask),1);
        return error;
    }
    case PTRACE_PEEKTEXT: case PTRACE_PEEKDATA: {
        if (!d->host.allowed(caller,pid)) return -EIO;
        /* The raw Linux syscall writes through data; libc returns the word. */
        if (!d->host.trace) return -ENOSYS;
        errno=0; long word=d->host.trace(op,pid,(void *)address,NULL);
        if (word==-1 && errno) return -errno;
        return transfer(caller,data,&word,sizeof(word),1);
    }
    case PTRACE_POKETEXT: case PTRACE_POKEDATA:
        return d->host.allowed(caller,pid) ? request(d,op,pid,address,(void *)data) : -EIO;
    case PTRACE_CONT: case PTRACE_SINGLESTEP: case PTRACE_SYSCALL: case PTRACE_SYSEMU: case PTRACE_DETACH: {
        if (data>64) return -EIO;
        struct md_signal_origin origin=p->origin;
        int delivery_stop=!p->syscall_stop && !((unsigned)p->status>>16);
        p->origin.valid=0;
        p->stopped=0; ready_remove(d,p); p->step=op==PTRACE_SINGLESTEP;
        p->syscall_mode=op==PTRACE_SYSCALL || op==PTRACE_SYSEMU ? op : 0;
        if (op==PTRACE_DETACH) {
            struct inferior **at=&d->inferiors;
            while (*at!=p) at=&(*at)->next;
            unlink_inferior(d,at); free(p); d->host.options(pid,0);
        }
        d->host.resume(pid,(int)data,&origin,delivery_stop); return 0;
    }
    default: return -EIO;
    }
}
static void wait_probe(struct md_debugger *d,struct waiting *w,enum md_debugger_wait_action action) {
    struct seccomp_data probe=w->call;
    if (w->filtered) {
        pid_t candidate=w->candidates[w->candidate];
        if (probe.nr==SYS_waitid) { probe.args[0]=P_PID; probe.args[1]=candidate; }
        else probe.args[0]=candidate;
    }
    w->probing=1;
    d->host.wait(w->pid,&probe,action);
}
static void wait_retry(struct md_debugger *d,struct waiting *w) {
    w->candidate=0; w->native_children=0; w->retry=0;
    if (w->filtered) {
        free(w->candidates); w->candidates=NULL; w->count=0;
        int filtered=wait_children(d,w->pid,&w->call,&w->candidates,&w->count,&w->native_children);
        if (filtered>=0) w->filtered=filtered;
        if (filtered<0 || (filtered && !w->count)) {
            md_debugger_wait_complete(d,w->pid,filtered<0 ? filtered : -ECHILD,NULL);
            return;
        }
    }
    wait_probe(d,w,MD_DEBUG_WAIT_REPROBE);
}
int md_debugger_call(struct md_debugger *d,pid_t pid,struct seccomp_data call) {
    if (call.nr!=SYS_wait4 && call.nr!=SYS_waitid && call.nr!=SYS_ptrace) return 0;
    if (call.nr==SYS_ptrace) {
        d->host.complete(pid,control(d,pid,&call)); return MD_DEBUG_CALL_HANDLED;
    }
    unsigned options=wait_options(&call);
    unsigned valid=WNOHANG|WUNTRACED|WCONTINUED|__WALL|__WCLONE|__WNOTHREAD;
    int id=call.nr==SYS_waitid;
    if (id) valid|=WEXITED|WNOWAIT;
    if ((options&~valid) || (id && (!(options&(WEXITED|WSTOPPED|WCONTINUED))
            || (call.args[0]!=P_ALL && call.args[0]!=P_PID && call.args[0]!=P_PGID && call.args[0]!=P_PIDFD)
            || (call.args[0]==P_PID && (int)call.args[1]<=0)))) {
        d->host.complete(pid,-EINVAL); return 1;
    }
    int children;
    int ready=wait_result(d,pid,&call,&children);
    if (ready) return ready;
    pid_t *candidates=NULL; size_t count=0; int live=0;
    int filtered=wait_children(d,pid,&call,&candidates,&count,&live);
    if (filtered<0) { free(candidates); d->host.complete(pid,filtered); return 1; }
    if (!children && !filtered) { free(candidates); return 0; }
    if (!children && filtered && !count && !live) { free(candidates); d->host.complete(pid,-ECHILD); return 1; }
    if (d->host.wait_admit && !d->host.wait_admit(pid)) { free(candidates); return MD_DEBUG_CALL_CONTEXT; }
    struct waiting *w=malloc(sizeof(*w));
    if (!w) { free(candidates); d->host.complete(pid,-ENOMEM); return 1; }
    *w=(struct waiting){.next=d->waiters,.pid=pid,.call=call,.probing=1,
        .filtered=filtered,.candidates=candidates,.count=count,.native_children=live}; d->waiters=w;
    if (filtered && !count) md_debugger_wait_complete(d,pid,-ECHILD,NULL);
    else wait_probe(d,w,MD_DEBUG_WAIT_PROBE);
    /* EVENT_WAIT: a guest trace stop or actual child exit resumes this wait.
     * Launch cancellation/timeout still owns both debugger and inferior. */
    return 1;
}
void md_debugger_wait_complete(struct md_debugger *d,pid_t pid,long value,const union md_process_wait *captured) {
    struct waiting **at=&d->waiters;
    while (*at && (*at)->pid!=pid) at=&(*at)->next;
    if (!*at) return;
    struct waiting *w=*at;
    int children=0, id=w->call.nr==SYS_waitid, result=0;
    if (id && value==0 && (w->call.args[2] || captured)) {
        siginfo_t info;
        int error=0;
        if (captured) info=captured->info;
        else error=transfer(pid,w->call.args[2],&info,sizeof(info),0);
        if (!error) {
            result=info.si_pid!=0;
            if (result) {
                pid_t reaped=info.si_pid;
                info.si_uid=visible_uid(d,pid,reaped,info.si_uid);
                info.si_pid=visible(d,pid,reaped);
                int error=w->call.args[2] ? transfer(pid,w->call.args[2],&info,sizeof(info),1) : 0;
                if (error) value=error;
                else if (!(wait_options(&w->call)&WNOWAIT) && (info.si_code==CLD_EXITED
                        || info.si_code==CLD_KILLED || info.si_code==CLD_DUMPED)
                        && d->host.reaped) d->host.reaped(pid,reaped,1);
            }
        }
    } else result=value>0;
    if (!result && (value==0 || value==-ECHILD) && w->filtered && w->candidate<w->count) {
        w->native_children|=value==0;
        if (++w->candidate<w->count) { wait_probe(d,w,MD_DEBUG_WAIT_REPROBE); return; }
    }
    if (result || (value<0 && value!=-ECHILD)) {
        if (!id && value>0) {
            pid_t reaped=(pid_t)value;
            value=visible(d,pid,reaped);
            int status;
            int observed=captured || (w->call.args[1]
                && !transfer(pid,w->call.args[1],&status,sizeof(status),0));
            if (captured) status=captured->status;
            if (observed && (WIFEXITED(status) || WIFSIGNALED(status)) && d->host.reaped)
                d->host.reaped(pid,reaped,1);
        }
        d->host.complete(pid,value);
    } else if (wait_result(d,pid,&w->call,&children)) {
        /* The queued trace event owns completion. */
    } else if (w->filtered) {
        if ((!children && !w->native_children) || (wait_options(&w->call)&WNOHANG)) {
            wait_empty(d,pid,&w->call,children || w->native_children ? 0 : -ECHILD);
        } else {
            w->probing=0;
            if (w->retry) wait_retry(d,w);
            else d->host.wait(pid,&w->call,MD_DEBUG_WAIT_PARK);
            return;
        }
    } else if (!children && !value && !(wait_options(&w->call)&WNOHANG)) {
        /* A native nonblocking probe may predate the final tracee exit event.
         * Once no virtual children remain, let the real parent reap normally. */
        struct seccomp_data call=w->call;
        *at=w->next; wait_free(w);
        d->host.wait(pid,&call,MD_DEBUG_WAIT_NATIVE); return;
    } else if (!children || (wait_options(&w->call)&WNOHANG)) {
        d->host.complete(pid,children ? 0 : value);
    } else {
        w->probing=0;
        if (w->retry) {
            w->retry=0; w->probing=1; d->host.wait(pid,&w->call,MD_DEBUG_WAIT_REPROBE);
        } else d->host.wait(pid,&w->call,MD_DEBUG_WAIT_PARK);
        return;
    }
    *at=w->next; wait_free(w);
}
void md_debugger_wait_resumed(struct md_debugger *d, pid_t pid, long error) {
    struct waiting **at=&d->waiters;
    while (*at && (*at)->pid!=pid) at=&(*at)->next;
    if (!*at) return;
    struct waiting *w=*at;
    if (!error) {
        int children;
        if (wait_result(d,pid,&w->call,&children)) {
            *at=w->next; wait_free(w); return;
        }
        wait_retry(d,w);
        return;
    }
    struct seccomp_data call=w->call;
    *at=w->next; wait_free(w);
    /* The kernel signal disposition, including SA_RESTART, owns interruption.
     * Forget the old wait before a handler can issue another wait itself. */
    if (error==-512) d->host.wait(pid,&call,MD_DEBUG_WAIT_RESTART);
    else d->host.complete(pid,error);
}
