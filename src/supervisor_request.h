#ifndef MD_SUPERVISOR_REQUEST_H
#define MD_SUPERVISOR_REQUEST_H

#include <asm/ptrace.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

/* Logical syscall input, independent of the transport that admitted it. */
static inline struct seccomp_data syscall_description(const struct user_pt_regs *regs) {
    struct seccomp_data call={.nr=regs->regs[8],.arch=AUDIT_ARCH_AARCH64,
        .instruction_pointer=regs->pc};
    for (unsigned i=0;i<6;++i) call.args[i]=regs->regs[i];
    return call;
}

/* A seccomp stop already supplies every syscall operand, without a GPR read. */
static inline struct seccomp_data syscall_observation(const struct ptrace_syscall_info *info) {
    struct seccomp_data call={.nr=info->seccomp.nr,.arch=info->arch,
        .instruction_pointer=info->instruction_pointer};
    for (unsigned i=0;i<6;++i) call.args[i]=info->seccomp.args[i];
    return call;
}

/* A debugger can change NT_ARM_SYSTEM_CALL independently of x8. Recovered
 * adapter contexts have a different PC and still use their logical frame. */
static inline struct seccomp_data syscall_stopped(const struct user_pt_regs *regs,
        const struct ptrace_syscall_info *info) {
    struct seccomp_data call=syscall_description(regs);
    if (info && (info->op==PTRACE_SYSCALL_INFO_SECCOMP || info->op==PTRACE_SYSCALL_INFO_ENTRY)
            && regs->pc==info->instruction_pointer)
        call.nr=info->seccomp.nr;
    return call;
}

/* ARM64 keeps orig_x0 separately: policy reads the entry argument even when
 * ptrace changes visible x0 for execution. The other arguments stay live. */
static inline struct seccomp_data syscall_policy(const struct user_pt_regs *regs,
        const struct ptrace_syscall_info *info) {
    struct seccomp_data call=syscall_stopped(regs,info);
    if (info && (info->op==PTRACE_SYSCALL_INFO_SECCOMP || info->op==PTRACE_SYSCALL_INFO_ENTRY)
            && regs->pc==info->instruction_pointer)
        call.args[0]=info->seccomp.args[0];
    return call;
}

struct supervisor_control_request {
    __u64 command;
    __u64 args[3];
};

static inline struct supervisor_control_request control_description(const struct user_pt_regs *regs) {
    return (struct supervisor_control_request){.command=regs->regs[0],
        .args={regs->regs[1],regs->regs[2],regs->regs[3]}};
}

#endif
