#define _GNU_SOURCE
#include "host_policy.h"
#include "cooperative_native.h"
#include "guest_debugger.h"
#include "guest_domain.h"
#include "guest_identity.h"
#include "interception_buffers.h"
#include "interception_memory.h"
#include "linux_abi.h"
#include "process_access.h"
#include "pid_calls.h"
#include "seccomp_policy.h"
#include "signal_origin.h"
#include "signal_pending.h"
#include "signal_view.h"
#include "supervisor_actors.h"
#include "supervisor_debug.h"
#include "supervisor_execution.h"
#include "supervisor_fs.h"
#include "supervisor_internal.h"
#include "supervisor_io.h"
#include "supervisor_memory.h"
#include "supervisor_notifications.h"
#include "supervisor_seccomp.h"
#include "supervisor_signals.h"
#include "supervisor_task.h"
#include "svc_machine.h"
#include "svc_registry.h"
#include "syscall_result.h"
#include "task_pending.h"
#include "task_status.h"
#include "signal_protocol.h"
#include <linux/audit.h>
static int debug_host_policy_visit(void *context,const siginfo_t *info);

void debugger_wait_release(struct thread *t) {
    retry_clear(t,RETRY_DEBUG_WAIT);
    if (t->debug.wait_output) {
        CHECK(!md_buffer_release(&t->debug.wait_output->buffer));
        free(t->debug.wait_output); t->debug.wait_output=NULL;
    }
}

int debugger_parent(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (t) {
        long parent=md_task_parent(pid);
        if (parent>=0) t->parent=(pid_t)parent;
    }
    return t ? t->parent : 0;
}

void debugger_reaped(pid_t observer,pid_t pid,int native_wait) {
    if (native_wait) process_reap(find_thread(observer),pid);
    else pid_collection_pending=1;
}

int debugger_group(pid_t pid) {
    struct thread *t=find_thread(pid);
    return t ? t->tgid : pid;
}

uid_t debugger_uid(pid_t pid) {
    struct thread *t=find_thread(pid);
    CHECK(t);
    return t->identity.uid.real;
}

int debugger_signal_mask(pid_t pid,int writing,uint64_t *mask) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    uint64_t native=writing ? *mask : 0;
    if (writing && t->signals.host) native&=~MD_SIGNAL_SYS_BIT;
    if (t->signals.delivery.active) {
        /* The carrier's temporary mask is not the application's mask. Keep
         * debugger changes in the same owner as an admitted sigprocmask. */
        if (writing) {
            int error=md_signal_delivery_update_mask(&t->signals.delivery,pid,native&md_signal_blockable_mask());
            if (error) return error;
        } else native=t->signals.delivery.mask;
    } else if (native_trace(writing ? PTRACE_SETSIGMASK : PTRACE_GETSIGMASK,pid,
            (void *)sizeof(native),&native)<0) return -errno;
    if (writing) {
        t->signals.handler_mask_known=0;
        if (t->signals.host) t->signals.host_blocked=!!(*mask&MD_SIGNAL_SYS_BIT);
    } else *mask=t->signals.host ? md_signal_view_mask(native,t->signals.host_blocked) : native;
    return 0;
}

uid_t debugger_visible_uid(pid_t observer,pid_t sender,uid_t fallback) {
    struct thread *t=find_thread(observer);
    return t ? process_signal_uid(t,sender,fallback) : fallback;
}

void debugger_signal_origin(pid_t recipient,const siginfo_t *info,struct md_signal_origin *origin,int consume) {
    struct thread *t=find_thread(recipient);
    if (t) {
        signal_origin_capture(t,info,origin);
        if (consume && origin->valid) signal_origin_consumed(t,info);
    }
}

/* Keep stop information native while a guest debugger owns it. Translate only
 * on actual delivery, in the recipient's namespaces rather than the tracer's. */
void debugger_signal_translate(pid_t observer,const struct md_signal_origin *origin,siginfo_t *info) {
    struct thread *t=find_thread(observer);
    if (t) signal_origin_translate(t,origin,info);
}

pid_t debugger_visible_pid(pid_t observer,pid_t native) {
    struct thread *t=find_thread(observer);
    return t ? visible_pid(t,native) : 0;
}

pid_t debugger_native_pid(pid_t observer,pid_t visible) {
    struct thread *t=find_thread(observer);
    return t ? native_pid(t,visible) : 0;
}

int inspect_allowed(pid_t caller, pid_t pid, int filesystem) {
    struct thread *from=find_thread(caller), *to=find_thread(pid);
    if (!from || !to || md_domain_restricted(from->resources.fs)) return 0;
    int allowed=from->tgid==to->tgid || md_process_may_inspect(&from->identity,&to->identity,filesystem,
        to->resources.access);
    if (!allowed) SUPERVISOR_TRACE("PROBE inspect-denied caller=%d target=%d filesystem=%d uid=%u/%u gid=%u/%u target-uid=%u/%u/%u target-gid=%u/%u/%u caps=%#llx/%#llx target-caps=%#llx dumpable=%d same-userns=%d\n",
        caller,pid,filesystem,from->identity.uid.real,from->identity.uid.fs,
        from->identity.gid.real,from->identity.gid.fs,
        to->identity.uid.real,to->identity.uid.effective,to->identity.uid.saved,
        to->identity.gid.real,to->identity.gid.effective,to->identity.gid.saved,
        (unsigned long long)from->identity.caps.permitted,(unsigned long long)from->identity.caps.effective,
        (unsigned long long)to->identity.caps.permitted,md_process_dumpable(to->resources.access),
        from->identity.user_namespace==to->identity.user_namespace);
    return allowed;
}

int debugger_allowed(pid_t caller, pid_t pid) {
    return inspect_allowed(caller,pid,0);
}

int debugger_traceme(pid_t parent,pid_t child) {
    struct thread *from=find_thread(parent), *to=find_thread(child);
    return from && to && !md_domain_restricted(from->resources.fs)
        && md_identity_traceme(&from->identity,&to->identity);
}

int proc_allowed(pid_t caller, pid_t pid) {
    return inspect_allowed(caller,pid,1);
}

static void debugger_call_retry(struct thread *t) {
    int result=debugger_call(t,&t->execution.request,entry_pending(t) ? NULL : &t->execution.registers);
    if (result==MD_DEBUG_CALL_CONTEXT) CHECK(entry_context(t,MD_CONTEXT_POLICY));
    else CHECK(result==MD_DEBUG_CALL_HANDLED);
}

int debugger_call(struct thread *t,const struct seccomp_data *call,const struct user_pt_regs *regs) {
    if (call->nr==SYS_ptrace)
        SUPERVISOR_TRACE("PROBE guest debugger caller=%d request=%llu target=%llu address=%#llx data=%#llx traced=%d\n",
            t->pid,(unsigned long long)call->args[0],(unsigned long long)call->args[1],
            (unsigned long long)call->args[2],(unsigned long long)call->args[3],
            md_debugger_traced(debugger,native_pid(t,(pid_t)call->args[1])));
    execution_retain(t,call,regs);
    if (call->nr==SYS_ptrace && call->args[0]!=PTRACE_TRACEME) {
        struct thread *target=find_thread(native_pid(t,(pid_t)call->args[1]));
        if (target && memory_access_defer(t,target->memory,debugger_call_retry)) return MD_DEBUG_CALL_HANDLED;
    }
    return md_debugger_call(debugger,t->pid,*call);
}

void debugger_complete(pid_t pid,long value) {
    struct thread *t=find_thread(pid);
    SUPERVISOR_TRACE("PROBE debugger result pid=%d value=%ld\n",pid,value);
    if (t) return_value(t,entry_pending(t) ? NULL : &t->execution.registers,value);
}

long debugger_trace(int request,pid_t pid,void *address,void *data) {
    struct thread *t=find_thread(pid);
    if (t && request==PTRACE_PEEKSIGINFO) {
        const struct ptrace_peeksiginfo_args *args=address;
        struct md_signal_pending_value pending;
        if (args->nr>0 && !(args->flags&~PTRACE_PEEKSIGINFO_SHARED)
                && md_signal_pending_peek_scope(t->signals.pending,args->flags&PTRACE_PEEKSIGINFO_SHARED
                    ? MD_SIGNAL_SHARED : MD_SIGNAL_PRIVATE,&pending)) {
            /* One logical standard-signal slot precedes the native queue.
             * Offsets address that same read-only view in every batch; native
             * realtime ordering and both queues' consumption stay unchanged. */
            struct ptrace_peeksiginfo_args native=*args;
            siginfo_t *items=data;
            int prefix=!native.off;
            if (prefix) { *items++=pending.info; --native.nr; }
            else --native.off;
            long count=native.nr ? native_trace(request,pid,&native,items) : 0;
            return count<0 ? count : prefix+count;
        }
    }
    if (t && t->seccomp.trace.stage==GUEST_TRACE_STOPPED && (uintptr_t)address==NT_ARM_SYSTEM_CALL
            && (request==PTRACE_GETREGSET || request==PTRACE_SETREGSET)) {
        struct iovec *io=data;
        if (io->iov_len%sizeof(int)) { errno=EINVAL; return -1; }
        if (!io->iov_len) return 0;
        if (request==PTRACE_GETREGSET) memcpy(io->iov_base,&t->seccomp.trace.number,sizeof(int));
        else memcpy(&t->seccomp.trace.number,io->iov_base,sizeof(int));
        io->iov_len=sizeof(int); return 0;
    }
    long result=native_trace(request,pid,address,data);
    if (result>=0 && t && request==PTRACE_SETREGSET && (uintptr_t)address==NT_PRSTATUS)
        t->debug.registers_written=1;
    return result;
}

int debugger_resume_entry(struct thread *t,int signal) {
    if (!t->debug.registers_written) return 0;
    t->debug.registers_written=0;
    if (t->kernel_resume==PTRACE_SYSEMU) return 0;
    struct ptrace_syscall_info info={0};
    if (!tracee_request(t,PTRACE_GET_SYSCALL_INFO,(void *)sizeof(info),&info,"debugger-mutated-entry")) return 1;
    if (info.op!=PTRACE_SYSCALL_INFO_ENTRY || (int)info.entry.nr<0) return 0;
    struct user_pt_regs regs;
    if (!registers(t->pid,&regs)) return 1;
    struct seccomp_data policy=syscall_policy(&regs,&info),execution=syscall_stopped(&regs,&info);
    if (policy.args[0]==execution.args[0]) return 0;
    uint32_t decision;
    CHECK(!md_seccomp_policy_eval(admission_policy(t),&policy,&decision));
    unsigned action=decision&SECCOMP_RET_ACTION_FULL;
    /* Policy reads orig_x0, while execution reads the tracer's x0. Conditional
     * selectors cannot admit that new resource by examining orig_x0 alone. */
    if ((action!=SECCOMP_RET_ALLOW && action!=SECCOMP_RET_LOG)
            || guest_notification_route(t,&execution)==MD_INTERCEPT_NATIVE) return 0;
    if (guest_trace_execution_begin(t,&policy,&regs)) resume(t->pid,signal);
    return 1;
}

int debugger_attachable(pid_t caller, pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t || debugger_group(caller)==debugger_group(pid) || !debugger_allowed(caller,pid)
            || !t->entered || !t->image.process_image) {
        SUPERVISOR_TRACE("PROBE debugger admission caller=%d target=%d state-or-identity-denied\n",caller,pid);
        return 0;
    }
    char byte;
    struct iovec local={&byte,1}, remote={(void *)t->image.process_image,1};
    ssize_t result=process_vm_readv(pid,&local,1,&remote,1,0);
    if (result!=1) SUPERVISOR_TRACE("PROBE debugger admission caller=%d target=%d image=%#lx read=%zd errno=%d\n",
        caller,pid,(unsigned long)t->image.process_image,result,errno);
    return result==1;
}

int debugger_interrupt(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    entry_wait_complete(t,-EINTR);
    /* An owned stop already queued by clone is itself the interruption boundary. */
    if (t->kernel_stopped || birth_stop_pending(t)) return 0;
    if (native_trace(PTRACE_INTERRUPT,pid,NULL,NULL)) return -errno;
    t->interrupt_pending=1; return 0;
}

int debugger_observe(pid_t owner) {
    struct thread *parent=find_thread(owner);
    if (!parent) return -ESRCH;
    /* EVENT_WAIT: a new trace relationship can select a wait already blocked
     * in the kernel, in any owner thread. INTERRUPT restarts it through the
     * debugger-aware path; cancellation/exit still owns the wait's lifetime. */
    for (struct thread *t=threads; t; t=t->next) if (t->pid && t->tgid==parent->tgid) {
        /* A retained shared request identifies its call without inspecting
         * registers. Only a native child wait needs debugger re-admission. */
        if (entry_pending(t) && t->execution.request.nr!=SYS_wait4
                && t->execution.request.nr!=SYS_waitid) continue;
        if (entry_pending(t) && t->entry.wait.complete) { entry_wait_complete(t,0); continue; }
        if (entry_pending(t) && debugger_wait_pending(t)) continue;
        int error=debugger_interrupt(t->pid);
        if (error && error!=-ESRCH) return error;
    }
    return 0;
}

int debugger_options(pid_t pid, unsigned long options) {
    struct thread *t=find_thread(pid);
    if (!t) return -ESRCH;
    unsigned long previous=t->debug.options;
    int dirty=t->trace_options_dirty;
    int changed=((t->debug.options^options)&PTRACE_O_TRACEEXIT) && !t->terminal_observation;
    t->debug.options=options;
    if (changed) t->trace_options_dirty=1;
    int error=task_trace_options(t);
    if (error) { t->debug.options=previous; t->trace_options_dirty=dirty; }
    return error;
}

void debugger_usage(pid_t pid, struct rusage *usage) {
    struct thread *t=find_thread(pid);
    *usage=t ? t->usage : (struct rusage){0};
}

int debugger_listen(pid_t pid) {
    struct thread *t=find_thread(pid);
    return t ? task_group_listen(t) : -ESRCH;
}

void debugger_wait_wake(pid_t pid) {
    struct thread *t=find_thread(pid);
    if (!t || t->debug.wait_waking) return;
    if (entry_pending(t)) {
        CHECK(t->entry.wait.complete);
        entry_wait_complete(t,0); return;
    }
    CHECK(t->phase==DEBUG_PARK_ENTRY || t->phase==DEBUG_PARK_EXIT);
    t->debug.wait_waking=1;
    /* EVENT_WAIT: the exact native poll stop must precede register changes.
     * An event before poll entry is consumed there without entering the wait. */
    if (t->phase==DEBUG_PARK_EXIT && !t->listening) {
        int error=debugger_interrupt(pid); CHECK(!error || error==-ESRCH);
    }
}

int debugger_wait_admit(pid_t pid) {
    struct thread *t=find_thread(pid);
    return t && (!entry_pending(t) || !checkpoint_restricted(pid));
}

static void debugger_wait_result(struct thread *t,long result) {
    union md_process_wait value,*captured=NULL;
    if (t->debug.wait_output) {
        struct md_buffer_span span;
        CHECK(!md_buffer_span(&t->debug.wait_output->buffer,&span));
        memcpy(&value,span.data,sizeof(value)); captured=&value;
        debugger_wait_release(t);
    }
    t->phase=IDLE;
    md_debugger_wait_complete(debugger,t->pid,result,captured);
    if (captured) adapter_progress();
}

static void debugger_entry_probed(struct thread *t,long result) {
    if (t->entry.effect_cancelled || md_syscall_restarting(result)) {
        debugger_wait_release(t);
        md_debugger_wait_resumed(debugger,t->pid,-512);
    } else debugger_wait_result(t,result);
}

static void debugger_entry_woken(struct thread *t,long result) {
    md_debugger_wait_resumed(debugger,t->pid,result==-EINTR ? -512 : result);
}

int debugger_wait_pending(const struct thread *t) {
    return t->entry.effect==debugger_entry_probed || t->phase==DEBUG_WAIT_ENTRY || t->phase==DEBUG_WAIT_EXIT;
}

void debugger_wait(pid_t pid,const struct seccomp_data *call,enum md_debugger_wait_action action) {
    struct thread *t=find_thread(pid);
    if (!t) return;
    int shared=entry_pending(t);
    int park=action==MD_DEBUG_WAIT_PARK_INITIAL || action==MD_DEBUG_WAIT_PARK;
    if (shared) {
        CHECK(t->phase==IDLE || t->phase==DEBUG_WAIT_BUFFER);
        t->phase=IDLE;
        if (action==MD_DEBUG_WAIT_RESTART) { entry_restart(t,RESTART_SIGNAL); return; }
        if (park) {
            CHECK(entry_wait_begin(t,INT64_MAX,debugger_entry_woken)); return;
        }
        if (action==MD_DEBUG_WAIT_NATIVE) {
            unsigned long cookie=MD_INTERCEPT_PROCESS;
            CHECK(process_call(t,call,NULL,&cookie)); return;
        }
    }
    const struct user_pt_regs *original=&t->execution.registers;
    uint64_t args[6]; memcpy(args,call->args,sizeof(args));
    unsigned index=call->nr==SYS_waitid ? 1 : 0;
    if ((action==MD_DEBUG_WAIT_PROBE || action==MD_DEBUG_WAIT_REPROBE)
            && (call->nr==SYS_wait4 || call->args[0]==P_PID || call->args[0]==P_PGID) && (pid_t)call->args[index]>0) {
        pid_t mapped=native_pid(t,(pid_t)call->args[index]);
        if (!mapped) {
            debugger_wait_release(t); t->phase=IDLE;
            md_debugger_wait_complete(debugger,pid,-ECHILD,NULL); return;
        }
        args[index]=mapped;
    }
    unsigned output=call->nr==SYS_waitid ? 2 : 1;
    if ((action==MD_DEBUG_WAIT_PROBE || action==MD_DEBUG_WAIT_REPROBE)
            && !call->args[output]) {
        retry_clear(t,RETRY_DEBUG_WAIT);
        if (!t->debug.wait_output) t->debug.wait_output=calloc(1,sizeof(*t->debug.wait_output));
        struct debug_wait_output *out=t->debug.wait_output;
        int error=out ? md_buffers_take(md_memory_buffers(t->memory),&out->buffer) : -ENOMEM;
        if (error==-EAGAIN) {
            out->call=*call; out->action=action;
            t->phase=DEBUG_WAIT_BUFFER; retry_wait(t,RETRY_DEBUG_WAIT); return;
        }
        if (error) {
            debugger_wait_release(t); t->phase=IDLE;
            md_debugger_wait_complete(debugger,pid,error,NULL); return;
        }
        struct md_buffer_span span; CHECK(!md_buffer_span(&out->buffer,&span));
        memset(span.data,0,sizeof(union md_process_wait));
        args[output]=md_memory_buffer_address(t->memory,&out->buffer); CHECK(args[output]);
    }
    if (shared) {
        args[call->nr==SYS_waitid ? 3 : 2]|=WNOHANG;
        entry_effect(t,call->nr,args,debugger_entry_probed); return;
    }
    struct user_pt_regs regs=*original;
    regs.regs[8]=call->nr; memcpy(regs.regs,args,sizeof(args));
    if (action==MD_DEBUG_WAIT_RESTART) { restart_call(t,original,t->debug.wait_mask,RESTART_SIGNAL); return; }
    if (park) {
        /* EVENT_WAIT: native interruptible poll delivers arbitrary guest
         * signals. Inferior events cancel it with INTERRUPT; no periodic wake
         * or descriptor is needed, and ordinary execution never enters here. */
        t->debug.wait_waking=0;
        /* Without a native probe the original wait is still pending; changing
         * x8 alone does not cancel the syscall latched by the kernel. */
        if (action==MD_DEBUG_WAIT_PARK_INITIAL
                && (!save_signal_mask(t,&t->debug.wait_mask,"debug-wait-mask") || !skip(pid))) return;
        if (!shield(t)) return;
        wait_poll_start(t,DEBUG_PARK_ENTRY);
        return;
    }
    SUPERVISOR_TRACE("PROBE debugger wait pid=%d nr=%llu target=%llu action=%d phase=%d\n",pid,regs.regs[8],regs.regs[0],action,t->phase);
    if (action!=MD_DEBUG_WAIT_PROBE) regs.pc-=4;
    if (action==MD_DEBUG_WAIT_NATIVE) t->phase=IDLE;
    else {
        /* Only the nonblocking probe is shielded. A handler must not replace
         * the replayed syscall; native blocking waits retain ordinary signals. */
        if (!save_signal_mask(t,&t->debug.wait_mask,"debug-wait-mask")
                || !shield(t)) return;
        regs.regs[call->nr==SYS_waitid ? 3 : 2]|=WNOHANG;
        t->phase=action==MD_DEBUG_WAIT_PROBE ? DEBUG_WAIT_EXIT : DEBUG_WAIT_ENTRY;
    }
    if (set_registers(pid,&regs)) resume(pid,0);
}

void debugger_wait_retry(struct thread *t) {
    struct debug_wait_output *out=t->debug.wait_output;
    CHECK(out && t->phase==DEBUG_WAIT_BUFFER);
    struct seccomp_data call=out->call;
    debugger_wait(t->pid,&call,out->action);
}

int debug_syscall_observed(struct thread *t,const struct ptrace_syscall_info *info) {
    int active=t->debug.call_active;
    t->debug.call_active=t->debug.adapter=0;
    return active && md_debugger_syscall_observed(debugger,t->pid,info);
}
int debug_syscall_exit(struct thread *t, const struct user_pt_regs *regs) {
    if (!t->debug.call_active) { t->debug.adapter=0; return 0; }
    struct user_pt_regs captured;
    if (!regs) {
        if (!registers(t->pid,&captured)) return 1;
        regs=&captured;
    }
    struct ptrace_syscall_info info={.op=PTRACE_SYSCALL_INFO_EXIT,.arch=AUDIT_ARCH_AARCH64,
        .instruction_pointer=regs->pc,.stack_pointer=regs->sp,
        .exit={.rval=(int64_t)regs->regs[0],.is_error=(uint64_t)regs->regs[0]>=(uint64_t)-4095}};
    return debug_syscall_observed(t,&info);
}

struct debug_host_policy_probe {
    struct thread *thread;
    struct seccomp_data *call;
    int number_known;
};
static int debug_host_policy_visit(void *context,const siginfo_t *info) {
    struct debug_host_policy_probe *probe=context;
    struct seccomp_data *call=probe->call;
    if (info->si_signo!=SIGSYS || info->si_code!=SYS_SECCOMP
            || info->si_arch!=call->arch
            || (uintptr_t)info->si_call_addr!=call->instruction_pointer) return 0;
    if (!probe->number_known) {
        /* Most exits have no host denial. Only a matching queued trap needs
         * the latched number, which a debugger may change independently of x8. */
        int number;
        struct iovec io={&number,sizeof(number)};
        if (!tracee_request(probe->thread,PTRACE_GETREGSET,(void *)NT_ARM_SYSTEM_CALL,&io,
                "debug-host-syscall")) return -ESRCH;
        call->nr=number; probe->number_known=1;
    }
    return info->si_syscall==call->nr;
}

int debug_host_policy_pending(struct thread *t,struct ptrace_syscall_info *info) {
    if (!t->signals.host || !t->debug.call_active || !t->entered) return 0;
    struct seccomp_data call={.arch=info->arch,.instruction_pointer=info->instruction_pointer};
    struct debug_host_policy_probe probe={.thread=t,.call=&call};
    int pending=md_task_pending_scan(native_trace,t->pid,debug_host_policy_visit,&probe);
    if (pending<=0) return pending;
    struct user_pt_regs regs;
    if (!registers(t->pid,&regs)) return -ESRCH;
    memcpy(call.args,regs.regs,sizeof(call.args));
    struct seccomp_data entry;
    int has_entry=debugger && md_debugger_syscall_entry(debugger,t->pid,&entry);
    if (has_entry) call.args[0]=entry.args[0];
    uint32_t decision;
    CHECK(!md_seccomp_policy_eval(admission_policy(t),&call,&decision));
    unsigned action=decision&SECCOMP_RET_ACTION_FULL;
    if (action==SECCOMP_RET_KILL_THREAD || action==SECCOMP_RET_KILL_PROCESS) {
        /* The kernel has already forced SIG_DFL and unblocked SIGSYS before
         * this exit stop. A debugger must not see the previous logical mask
         * and mistake fatal seccomp for a completed injected operation. */
        signal_host_fatal(t);
        return 0;
    }
    if (action==SECCOMP_RET_TRACE && has_entry) {
        /* Publish guest TRACE while the real kernel exit is still available.
         * A skipped call can then return at that exact boundary: injecting a
         * signal at its exit must queue it, not replace the pending host trap. */
        t->debug.host_completed_pc=call.instruction_pointer;
        t->debug.host_completed_number=call.nr;
        CHECK(guest_trace_begin(t,&call,&regs,NULL,MD_TASK_CALL_EXIT));
        return 2;
    }
    if (action==SECCOMP_RET_ALLOW || action==SECCOMP_RET_LOG) {
        decision=host_policy_interception(&call);
        action=decision&SECCOMP_RET_ACTION_FULL;
    }
    if (action==SECCOMP_RET_ERRNO) {
        /* A scalar denial is already complete at the native exit. Publish it
         * there so debugger signal injection keeps syscall-stop semantics.
         * Consume the exact pending host trap later without overwriting any
         * registers the debugger changes after observing this result. */
        long result=md_seccomp_policy_error(decision);
        if (!set_stopped_result(t,result)) return -ESRCH;
        info->exit.rval=result; info->exit.is_error=(uint64_t)result>=(uint64_t)-4095;
        t->debug.host_completed_pc=call.instruction_pointer;
        t->debug.host_completed_number=call.nr;
        return 0;
    }
    /* Guest TRAP and unsupported host calls retain native exit-then-signal
     * ordering. Only an owned adapter defers the debugger's result. */
    return action==SECCOMP_RET_TRACE || action==SECCOMP_RET_USER_NOTIF;
}

int debug_host_policy_completed(struct thread *t,const siginfo_t *info) {
    if (!t->debug.host_completed_pc || info->si_signo!=SIGSYS || info->si_code!=SYS_SECCOMP
            || info->si_arch!=AUDIT_ARCH_AARCH64 || info->si_syscall!=t->debug.host_completed_number
            || (uintptr_t)info->si_call_addr!=t->debug.host_completed_pc) return 0;
    t->debug.host_completed_pc=0;
    return 1;
}

int debugger_at_boundary(const struct thread *t) {
    /* Re-admission after TRACE is still the selected syscall. Debugger
     * SYSEMU/step/interrupt applies after this owned replay, not to its gate. */
    return t->phase==IDLE && !t->metadata_restart && !t->descriptors.running && !t->descriptors.order.table && !t->descriptors.fs_order.fs
        && !t->descriptors.policy_order.queue && !t->memory_op.order.queue && !t->memory_op.files.table
        && !t->signals.delivery.active && t->seccomp.trace.stage!=GUEST_TRACE_REPLAY
        && t->seccomp.trace.stage!=GUEST_TRACE_EXECUTION
        && t->seccomp.trace.stage!=GUEST_TRACE_ADMISSION
        && t->seccomp.trace.stage!=GUEST_TRACE_DRAIN;
}

int debugger_context_ready(struct thread *t) {
    struct md_svc_registry *machine=md_memory_svc(t->memory);
    if (machine && md_debugger_traced(debugger,t->pid)) {
        /* An interrupt can land inside a resident entry, outside the syscall
         * adapter. Retire that frame before exposing registers to the debugger;
         * a running payload finishes through its existing return checkpoint. */
        if (!svc_entry_observe(t)) return 0;
        int deferred=md_svc_machine_flush(native_trace,machine,&t->machine,t->pid);
        if (deferred==-ESRCH) { t->resume_lost=1; return 0; }
        CHECK(deferred>=0);
        if (deferred) { t->machine.draining=1; return 0; }
    }
    return 1;
}

int debugger_boundary(struct thread *t) {
    if (!debugger_at_boundary(t) || !md_debugger_stop_pending(debugger,t->pid)
            || !debugger_context_ready(t)) return 0;
    if (md_debugger_stop_pending(debugger,t->pid)) {
        struct ptrace_syscall_info info={0};
        if (!tracee_request(t,PTRACE_GET_SYSCALL_INFO,(void *)sizeof(info),&info,
                "debugger-interrupt-boundary")) return 0;
        if (info.op!=PTRACE_SYSCALL_INFO_NONE) {
            /* ARM64 hides application x7 while reporting a syscall stop.
             * An interrupt must leave that kernel boundary before publishing
             * ordinary registers, including after a skipped SYSEMU entry. */
            if (!t->interrupt_pending)
                tracee_request(t,PTRACE_INTERRUPT,NULL,NULL,"debugger-interrupt-commit");
            return 0;
        }
    }
    return md_debugger_boundary(debugger,t->pid);
}

void debugger_park_complete(struct thread *t,int cancelled) {
    long value=0;
    if (!cancelled) {
        struct user_pt_regs regs;
        if (!registers(t->pid,&regs)) return;
        value=(long)regs.regs[0];
    }
    int waking=t->debug.wait_waking; t->debug.wait_waking=0;
    CHECK(!cancelled || waking);
    int interrupted=md_syscall_restarting(value);
    SUPERVISOR_TRACE("PROBE debugger park pid=%d value=%ld waking=%d\n",t->pid,value,waking);
    t->phase=IDLE;
    if (!signal_mask(t,t->debug.wait_mask,"debug-park-unmask")) return;
    md_debugger_wait_resumed(debugger,t->pid,waking && (cancelled || interrupted || value==-ENOSYS || !value) ? 0
        : interrupted ? -512 : value<0 ? value : -EIO);
}

int debug_wait_exit(struct thread *t,pid_t pid) {
    if (t->phase==DEBUG_WAIT_ENTRY) {
        t->phase=DEBUG_WAIT_EXIT; resume(pid,0); return 1;
    }
    if (t->phase==DEBUG_WAIT_EXIT) {
        struct user_pt_regs regs;
        if (!registers(pid,&regs)) return 1;
        if (!signal_mask(t,t->debug.wait_mask,"debug-wait-unmask")) return 1;
        debugger_wait_result(t,(long)regs.regs[0]);
        return 1;
    }
    if (t->phase==DEBUG_PARK_ENTRY) {
        int entered=wait_poll_entry(t);
        if (entered<=0) { if (!entered) resume(pid,0); return 1; }
        if (t->debug.wait_waking) {
            wait_cancel_entry(t,DEBUG_PARK_EXIT);
            return 1;
        } else if (!signal_mask(t,t->debug.wait_mask,"debug-park-unmask")) return 1;
        t->phase=DEBUG_PARK_EXIT; resume(pid,0); return 1;
    }
    if (t->phase==DEBUG_PARK_EXIT) { debugger_park_complete(t,0); return 1; }
    return 0;
}
