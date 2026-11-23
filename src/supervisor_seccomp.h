#ifndef MD_SUPERVISOR_SECCOMP_H
#define MD_SUPERVISOR_SECCOMP_H

#include "supervisor_thread.h"
#include "seccomp_capture.h"
#include "seccomp_notify.h"
#include "task_copy.h"

struct filter_install {
    struct md_resource_order memory;
    struct md_fd_order files;
    struct md_fd_origin_update listener;
    struct md_interception_buffer scratch;
    struct md_task_copy copy;
    struct md_seccomp_capture capture;
    struct md_task_call admission;
    struct task_action *loan;
    struct sock_fprog program;
    struct sock_filter code[BPF_MAXINSNS];
    unsigned stage;
    unsigned selectors;
    int checkpoint_suspended, virtual_listener, source, admitted, native_completed, retiring;
    long error;
};

struct guest_notification {
    struct md_task_call call;
    struct md_seccomp_notify *queue;
    struct md_seccomp_notification *message;
    struct seccomp_data original;
    siginfo_t host_signal;
    int checkpoint_suspended,continuing_native,promoting;
};
struct ptrace_syscall_info;

extern struct md_task_quiesce *policy_barrier;
extern struct thread *policy_installer;

struct md_seccomp_policy *admission_policy(const struct thread *t);
enum { FILTER_SERVICE_GATES=1 };
void filter_service_gates(struct md_seccomp_gate gates[FILTER_SERVICE_GATES]);

int guest_trace_begin(struct thread *,const struct seccomp_data *,const struct user_pt_regs *,
        const struct seccomp_notif *,enum md_task_call_boundary);
void guest_trace_promoted(struct thread *,const struct user_pt_regs *);
int guest_trace_recheck(struct thread *,const struct seccomp_data *);
int guest_trace_resume(struct thread *,int signal);
int guest_trace_syscall(struct thread *,const struct ptrace_syscall_info *,struct user_pt_regs *);
const struct seccomp_data *guest_trace_drain_exit(struct thread *);
int guest_trace_execution(struct thread *,struct ptrace_syscall_info *,struct user_pt_regs *);
int guest_trace_execution_begin(struct thread *,const struct seccomp_data *,struct user_pt_regs *);
void guest_notification_discard(struct thread *t);
int guest_notification_begin(struct thread *t,const struct seccomp_data *data,
        const struct user_pt_regs *regs,const struct seccomp_notif *kernel,const siginfo_t *host_signal);
int guest_notification_kernel(struct thread *t,const struct seccomp_notif *q);
int guest_notification_event(struct thread *t,int status);
unsigned long guest_notification_route(struct thread *t,const struct seccomp_data *call);
uint32_t host_policy_interception(const struct seccomp_data *call);
int host_policy_signal(struct thread *t,struct md_task_signal_stop *stop);
int filter_revoke_entry(struct thread *t,const struct seccomp_data *call);
int filter_entry_eligible(const struct thread *t);
void filter_entry_rearm(struct thread *t);
void filter_entry_complete(struct thread *t);
int filter_entry_map(struct thread *t,const struct user_pt_regs *regs,
        void (*complete)(struct thread *,const struct user_pt_regs *));
void filter_install_discard(struct thread *t);
void filter_install_fail(struct thread *t,int error);

int filter_listener_notification(struct thread *t,const struct seccomp_notif *q);

void policy_sync_progress(void);
int filter_selectors_required(const struct thread *t);
void filter_install_progress(struct thread *t);
int filter_install_event(struct thread *t,int status);
void filter_install_begin(struct thread *t,const struct seccomp_data *call,const struct user_pt_regs *r);
int filter_observed(struct thread *t,const struct user_pt_regs *regs);

int describe_filter(pid_t pid,const struct seccomp_data *call);

uint32_t interception_decision(struct thread *t,const struct seccomp_data *call);

#endif
