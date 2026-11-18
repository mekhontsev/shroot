#ifndef MD_INTERCEPTION_PROGRAM_H
#define MD_INTERCEPTION_PROGRAM_H
#include "interception.h"
#include "fd_filter_program.h"
#include "descriptor_calls.h"
#include "file_calls.h"
#include "socket_calls.h"
#include "guest_domain.h"
#include "identity_call.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

enum { MD_INTERCEPTION_PROGRAM_INSTRUCTIONS=1024 };
struct md_interception_program {
    unsigned short count;
    struct sock_filter code[MD_INTERCEPTION_PROGRAM_INSTRUCTIONS];
};
struct md_interception_site { uintptr_t pc; int number; uint32_t result; };
/* Group exact sites by their high word. PIE may cross a 4 GiB boundary;
 * the usual single-group layout still rejects ordinary PCs with one check. */
static inline unsigned md_interception_sites(const struct md_interception_site *sites,
        unsigned count,struct sock_filter *out) {
    unsigned used=0;
    for (unsigned i=0;i<count;++i) {
        uint32_t high=(uint32_t)(sites[i].pc>>32);
        unsigned prior=0;
        while (prior<i && (uint32_t)(sites[prior].pc>>32)!=high) ++prior;
        if (prior<i) continue;
        out[used++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data,instruction_pointer)+4);
        unsigned branch=used++;
        int low_loaded=0;
        for (unsigned j=i;j<count;++j) {
            const struct md_interception_site *s=sites+j;
            if ((uint32_t)(s->pc>>32)!=high) continue;
            if (!low_loaded) out[used++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                offsetof(struct seccomp_data,instruction_pointer));
            out[used++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,
                (uint32_t)s->pc,0,s->number<0 ? 1 : 3);
            if (s->number>=0) {
                out[used++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                    offsetof(struct seccomp_data,nr));
                out[used++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,s->number,0,1);
            }
            out[used++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,s->result);
            low_loaded=s->number<0;
        }
        out[branch]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,high,0,used-branch-1);
    }
    return used;
}
enum { MD_SIGNAL_SERVICE_INSTRUCTIONS=4*5+1, MD_SIGNAL_QUERY_INSTRUCTIONS=6+MD_SIGNAL_SERVICE_INSTRUCTIONS };
static inline unsigned md_signal_service_program(const struct md_interception_abi *abi,
        uint32_t fallback,struct sock_filter *out) {
    const uintptr_t sites[]={abi->raw_gate,abi->task_return,abi->native_return,abi->adapter_native_return};
    unsigned count=0;
    for (unsigned i=0;i<sizeof(sites)/sizeof(*sites);++i) {
        const struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(sites[i]>>32),0,3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)sites[i],0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        for (unsigned n=0;n<sizeof(code)/sizeof(*code);++n) out[count++]=code[n];
    }
    out[count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,fallback);
    return count;
}
static inline unsigned md_signal_query_program(const struct md_interception_abi *abi,
        uint32_t result,struct sock_filter *out) {
    if (!abi->host_policy) return 0;
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigprocmask,0,MD_SIGNAL_QUERY_INSTRUCTIONS-2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,MD_SIGNAL_QUERY_INSTRUCTIONS-4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,MD_SIGNAL_QUERY_INSTRUCTIONS-6)};
    unsigned count=sizeof(code)/sizeof(*code);
    for (unsigned i=0;i<count;++i) out[i]=code[i];
    return count+md_signal_service_program(abi,result,out+count);
}
/* One definition for native installation and original-call continuation.
 * Reconstruct only on a cold USER_NOTIF CONTINUE, never on ordinary syscalls. */
static inline void md_interception_program_build(const struct md_interception_abi *abi,
        struct md_interception_program *out) {
    uintptr_t gate=abi->raw_gate,watch=abi->watch_return,capture=abi->capture_gate;
    uintptr_t task=abi->task_return,abort_task=abi->task_abort_return;
    uintptr_t admit=abi->buffer_admit,native=abi->native_return;
#define COUNT(name) + 1
        enum { transport_instructions = 2 * (2 MD_GATE_TRANSPORT_CALLS(COUNT)
            MD_GATE_FILE_EFFECT_CALLS(COUNT)) };
#undef COUNT
#define COUNT_QUERY(name,value) + 5
        enum { query_instructions = 0 MD_DESCRIPTOR_SERVICE_QUERIES(COUNT_QUERY) };
#undef COUNT_QUERY
#define TRACE(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_DISPATCH),
#define OBSERVE(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_OBSERVE),
#define NATIVE(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#define DESCRIPTOR(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_FD),
/* Compare the full policy argument, not only its low kernel int. */
#define NATIVE_ARGUMENT(n, index, value) \
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 6), \
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[index]) + 4), \
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3), \
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[index])), \
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1), \
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        struct sock_filter prefix[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            /* Fixed-number service markers cannot alias these calls. Linux
             * can cache these decisions without reading IP or arguments;
             * later descriptor selectors and application filters still apply. */
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            /* Task-affine epoll registration borrows its auxiliary queue via
             * the already-admitted ctl call, preserving application policy. */
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_ctl,0,5),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(admit>>32),0,3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)admit,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            MD_DOMAIN_WAIT_CALLS(NATIVE)
            /* A blocking epoll wait can acquire virtual interests after it
             * starts. Admit its owner before sleeping, but leave zero-time
             * native probes and owned task/adapter calls in the kernel. */
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_pwait2,1,0),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_pwait,0,0)};
        const struct md_interception_site waits[]={
            {admit,-1,SECCOMP_RET_USER_NOTIF},{native,-1,SECCOMP_RET_ALLOW},
            {task,-1,SECCOMP_RET_ALLOW},{gate,-1,SECCOMP_RET_ALLOW}};
        struct sock_filter wait_tail[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_epoll_pwait2,3,0),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_READINESS),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            MD_DOMAIN_EXECUTION_CALLS(NATIVE)};
        const struct md_interception_site services[]={
#define MARKER(field,symbol) \
            {abi->field+4,-1,SECCOMP_RET_TRACE|MD_INTERCEPT_CHECKPOINT},
            MD_CHECKPOINT_SITES(MARKER)
#undef MARKER
            {abi->adapter_native_return,-1,SECCOMP_RET_TRACE|MD_INTERCEPT_TASK},
            /* The operation owner has admitted this journaled native effect.
             * Do not maintain a second syscall policy at its execution gate. */
            {native,-1,SECCOMP_RET_ALLOW},
            /* Descriptor admission has no dependency on application prctl
             * policy. The installed chain must admit this exact service site. */
            {admit,SYS_gettid,SECCOMP_RET_USER_NOTIF},
            /* Exact private-helper termination site. Its admitted service
             * policy must not strand the private file table because ordinary
             * guest exit is denied. Guest exits never use this site. */
            {abort_task,-1,SECCOMP_RET_KILL_THREAD},
            {task,SYS_gettid,SECCOMP_RET_USER_NOTIF},
            {task,-1,SECCOMP_RET_TRACE|MD_INTERCEPT_TASK},
            /* Declared on the original listener; a later listenerless filter
             * cannot acquire or inherit USER_NOTIF delivery. */
            {watch,-1,SECCOMP_RET_USER_NOTIF},
            {capture,SYS_openat,SECCOMP_RET_TRACE|MD_INTERCEPT_CAPTURE}};
        struct sock_filter filter[]={
            /* Descriptor metadata must remain serviceable after an application
             * installs a higher-precedence filter or becomes nondumpable. */
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 10),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_PID_SIGNAL_GROUP, 6, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_FD_CHANNEL, 5, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_BUFFER, 4, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_PROC_IMAGE, 3, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_SHM, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_IPC, 1, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MD_GUEST_MAP_IMAGE, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            DESCRIPTOR(clone) DESCRIPTOR(clone3) OBSERVE(chroot) OBSERVE(waitid) DESCRIPTOR(signalfd4)
            MD_FD_CLOSE_FILTER,
            MD_DOMAIN_FD_CALLS(DESCRIPTOR)
            /* Descriptor commands use the kernel's unsigned-int argument. */
#define FD_ARGUMENT(n, index, value) \
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 4), \
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[index])), \
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 1), \
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_FD), \
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            MD_DOMAIN_FD_ARGUMENTS(FD_ARGUMENT)
#undef FD_ARGUMENT
            /* No peer address or ancillary result needs adaptation. Provider
             * FD selectors retain virtual socket ownership, just as for IO. */
            NATIVE_ARGUMENT(sendto,4,0) NATIVE_ARGUMENT(recvfrom,4,0)
            NATIVE(read) NATIVE(write) NATIVE(readv) NATIVE(writev)
            NATIVE(pread64) NATIVE(pwrite64)
            /* Internal mappings, admitted regular-file cursors and descriptor
             * capacity use native resources, not a second guest operation. */
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)+4),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(gate>>32),0,15),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,instruction_pointer)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)gate,0,13),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            NATIVE(mmap) NATIVE(munmap) NATIVE(mremap) NATIVE(mprotect)
            NATIVE(prlimit64) NATIVE(lseek)
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            /* File mappings require their descriptor's live mount policy.
             * Anonymous non-replacing mappings and ordinary data IO stay native. */
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,6),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])),
            BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_FIXED,2,0),
            BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_ANONYMOUS,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_MEMORY),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_munmap,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_MEMORY),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mremap,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_MEMORY),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,4),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
            BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,PROT_EXEC,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_MEMORY),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            NATIVE(getpid) NATIVE(getppid) NATIVE(gettid)
            NATIVE(eventfd2) NATIVE(timerfd_create) NATIVE(timerfd_settime) NATIVE(timerfd_gettime)
            NATIVE(exit) NATIVE(exit_group) NATIVE(set_tid_address)
            /* Only guest-owned limits need adaptation; all other limits keep
             * their native behavior and application seccomp still takes precedence. */
#define LIMIT(n, index) \
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,5), \
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[index])), \
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,RLIMIT_NPROC,1,0), \
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,RLIMIT_NOFILE,0,1), \
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_IDENTITY), \
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            LIMIT(getrlimit,0) LIMIT(setrlimit,0) LIMIT(prlimit64,1)
#undef LIMIT
            MD_DOMAIN_KERNEL_CONTROL_CALLS(NATIVE)
            MD_DOMAIN_KERNEL_ARGUMENTS(NATIVE_ARGUMENT)
#undef NATIVE_ARGUMENT
            /* Report missing guest providers without exposing host resources.
             * Application ERRNO/TRAP/KILL filters still apply. */
#define UNAVAILABLE(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1), \
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
            MD_UNAVAILABLE_CALLS(UNAVAILABLE)
#undef UNAVAILABLE
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(gate >> 32), 0, 22 + transport_instructions + query_instructions),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)gate, 0, 20 + transport_instructions + query_instructions),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            /* Already unconditional kernel operations in every domain. The
             * original call enters its adapter after guest policy admission;
             * admitted service gates do not repeat the guest program. */
            MD_GATE_TRANSPORT_CALLS(NATIVE)
            /* The filesystem owner has already selected the native effect.
             * Reentering the supervisor cannot add another policy decision. */
            MD_GATE_FILE_EFFECT_CALLS(NATIVE)
            /* Only the admitted raw gate can wake the native control owner;
             * application signal sends still pass through the signal owner. */
            NATIVE(rt_tgsigqueueinfo)
            /* These admitted internal queries request native metadata/paths,
             * never logical guest metadata. */
            NATIVE(fstat) NATIVE(readlinkat)
            /* The adapter requests the carrier's native state after original
             * guest-policy admission. These queries neither mutate slots nor
             * require an exit observer. Match the kernel's command width. */
#define NATIVE_QUERY(name,value) \
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##name,0,4), \
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])), \
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,value,0,1), \
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), \
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            MD_DESCRIPTOR_SERVICE_QUERIES(NATIVE_QUERY)
#undef NATIVE_QUERY
            /* Runtime transport validates its native peer identity; guest
             * credential queries use their original SVC, never this gate. */
            NATIVE(getuid) NATIVE(geteuid) NATIVE(getgid) NATIVE(getegid)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_chdir, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_CWD),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fchdir, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_CWD),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_EXEC),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_EXEC),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_NATIVE),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            TRACE(uname) TRACE(sethostname) TRACE(setdomainname) TRACE(reboot)
#define IDENTITY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_IDENTITY),
            MD_IDENTITY_CALLS(IDENTITY)
            TRACE(shmget) TRACE(shmat) TRACE(shmdt) TRACE(shmctl)
            TRACE(semget) TRACE(semctl) TRACE(semop) TRACE(semtimedop)
            TRACE(msgget) TRACE(msgctl) TRACE(msgsnd) TRACE(msgrcv)
#undef IDENTITY
            OBSERVE(unshare) OBSERVE(setns) OBSERVE(get_robust_list)
            OBSERVE(seccomp)
#define NOTIFY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1), \
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_USER_NOTIF),
            MD_FS_NOTIFICATION_CALLS(NOTIFY)
#undef NOTIFY
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 7),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_OBSERVE),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_DUMPABLE, 1, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_DUMPABLE, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_IDENTITY),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            MD_FILE_TASK_CALLS(TRACE)
            TRACE(inotify_init1) TRACE(inotify_rm_watch)
            TRACE(recvmmsg)
            MD_SOCKET_CALLS(TRACE)
            TRACE(execve) TRACE(execveat)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | MD_INTERCEPT_NATIVE)
        };
#undef TRACE
#undef OBSERVE
#undef NATIVE
#undef DESCRIPTOR

    _Static_assert((sizeof(prefix)+sizeof(wait_tail)+sizeof(filter))/sizeof(*filter)
        +7*(sizeof(waits)/sizeof(*waits)+sizeof(services)/sizeof(*services))
        +MD_SIGNAL_QUERY_INSTRUCTIONS<=MD_INTERCEPTION_PROGRAM_INSTRUCTIONS,"interception filter capacity");
    _Static_assert(5*sizeof(services)/sizeof(*services)<256,"service group branch capacity");
    for (unsigned i=0;i<3;++i) out->code[i]=prefix[i];
    unsigned query=md_signal_query_program(abi,SECCOMP_RET_USER_NOTIF,out->code+3);
    unsigned used=3+query;
    for (unsigned i=3;i<sizeof(prefix)/sizeof(*prefix);++i) out->code[used++]=prefix[i];
    unsigned wait_branch=used-1;
    unsigned wait_count=md_interception_sites(waits,sizeof(waits)/sizeof(*waits),out->code+used);
    out->code[wait_branch].jf=wait_count+6;
    used+=wait_count;
    for (unsigned i=0;i<sizeof(wait_tail)/sizeof(*wait_tail);++i) out->code[used++]=wait_tail[i];
    used+=md_interception_sites(services,sizeof(services)/sizeof(*services),out->code+used);
    for (unsigned i=0;i<sizeof(filter)/sizeof(*filter);++i) out->code[used++]=filter[i];
    out->count=used;
}
static inline void md_signal_program_build(const struct md_interception_abi *abi,
        struct md_interception_program *out) {
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_signalfd4,39,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigaction,38,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigprocmask,37,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigpending,36,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigreturn,35,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigtimedwait,34,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_rt_sigsuspend,33,0),
#define MASKED_WAIT(n,arg,remaining) \
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,7), \
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[arg])), \
        BPF_STMT(BPF_MISC|BPF_TAX,0), \
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[arg])+4), \
        BPF_STMT(BPF_ALU|BPF_OR|BPF_X,0), \
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1), \
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), \
        BPF_STMT(BPF_JMP|BPF_JA,remaining),
        MASKED_WAIT(ppoll,3,25)
        MASKED_WAIT(pselect6,5,17)
        MASKED_WAIT(epoll_pwait,4,9)
        MASKED_WAIT(epoll_pwait2,4,1)
#undef MASKED_WAIT
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};

    unsigned query=md_signal_query_program(abi,SECCOMP_RET_ALLOW,out->code);
    out->count=sizeof(code)/sizeof(*code)+query;
    for (unsigned i=0;i<sizeof(code)/sizeof(*code);++i) out->code[i+query]=code[i];
    out->count+=md_signal_service_program(abi,SECCOMP_RET_TRACE|MD_INTERCEPT_SIGNAL,out->code+out->count);
}
#endif
