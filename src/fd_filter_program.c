#define _GNU_SOURCE
#include "fd_filter_program.h"
#include "interception.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

unsigned md_fd_filter_instructions(const struct md_fd_filter_program *p) {
    unsigned count=3+p->count;
    for (unsigned i=0;i<p->count;++i) {
        const struct sock_filter *at=p->code+i;
        if (at->code==(BPF_RET|BPF_K)) ++count;
        else if (BPF_CLASS(at->code)==BPF_JMP && BPF_OP(at->code)!=BPF_JA) {
            count+=BPF_SRC(at->code)==BPF_K && at->k>INT32_MAX;
            count+=at->jf && (at->jt || BPF_OP(at->code)==BPF_JSET);
        }
    }
    return count;
}

/* Runtime gates normally share one code mapping. Group their high words so
 * every persistent selector does not spend five instructions per gate. */
static void exemptions(const struct md_fd_filter_gates *gates,struct md_fd_filter_program *out) {
    const uintptr_t addresses[]={gates->raw,gates->watch,gates->task,gates->native,gates->adapter};
    _Static_assert(sizeof(addresses)/sizeof(*addresses)==MD_FD_FILTER_GATES,"FD gate capacity");
    unsigned seen=0;
    for (unsigned i=0;i<sizeof(addresses)/sizeof(*addresses);++i) {
        if (!addresses[i] || (seen&(1u<<i))) continue;
        unsigned low[MD_FD_FILTER_GATES],count=0,high=(unsigned)(addresses[i]>>32);
        for (unsigned j=i;j<sizeof(addresses)/sizeof(*addresses);++j)
            if (addresses[j] && (unsigned)(addresses[j]>>32)==high) {
                seen|=1u<<j;
                unsigned k=0;
                while (k<count && low[k]!=(unsigned)addresses[j]) ++k;
                if (k==count) low[count++]=(unsigned)addresses[j];
            }
        out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data,instruction_pointer)+4);
        out->code[out->count++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,high,0,1+2*count);
        out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
            offsetof(struct seccomp_data,instruction_pointer));
        for (unsigned k=0;k<count;++k) {
            out->code[out->count++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,low[k],0,1);
            out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
        }
    }
}
static void compact_all_descriptors(struct md_fd_filter_program *out) {
    unsigned positions[MD_FD_FILTER_INSTRUCTIONS+1],used=0;
    unsigned char removed[MD_FD_FILTER_INSTRUCTIONS]={0};
    /* All-FD selectors need no masked FD comparison. Preserve the generated
     * branch graph, including WATCH's two argument-loading entry points. */
    for (unsigned i=0;i+1<out->count;++i) {
        const struct sock_filter *a=&out->code[i],*b=a+1;
        if (a->code==(BPF_ALU|BPF_AND|BPF_K) && !a->k
                && b->code==(BPF_JMP|BPF_JEQ|BPF_K) && !b->k && !b->jt && b->jf==1) {
            removed[i]=removed[i+1]=1;
            if (i && out->code[i-1].code==(BPF_LD|BPF_W|BPF_ABS)
                    && out->code[i-1].k>=offsetof(struct seccomp_data,args)) removed[i-1]=1;
        }
    }
    /* Once FD comparisons disappear, their false edges still hold nr in A.
     * Merge predecessor facts before removing the now redundant reloads. */
    unsigned char accumulator[MD_FD_FILTER_INSTRUCTIONS+1]={0}; accumulator[0]=2;
    for (unsigned i=0;i<out->count;++i) {
        const struct sock_filter *at=out->code+i;
        unsigned value=accumulator[i];
        if (!removed[i]) {
            if (at->code==(BPF_LD|BPF_W|BPF_ABS)) {
                if (at->k==offsetof(struct seccomp_data,nr)) {
                    if (value==1) removed[i]=1;
                    value=1;
                } else value=2;
            } else if (BPF_CLASS(at->code)==BPF_RET) continue;
            else if (BPF_CLASS(at->code)==BPF_JMP) {
                if (BPF_OP(at->code)==BPF_JA) accumulator[i+1+at->k]|=value;
                else { accumulator[i+1+at->jt]|=value; accumulator[i+1+at->jf]|=value; }
                continue;
            } else value=2;
        }
        accumulator[i+1]|=value;
    }
    for (unsigned i=0;i<out->count;++i) { positions[i]=used; used+=!removed[i]; }
    positions[out->count]=used;
    for (unsigned i=0;i<out->count;++i) if (!removed[i]) {
        struct sock_filter code=out->code[i];
        if (BPF_CLASS(code.code)==BPF_JMP) {
            if (BPF_OP(code.code)==BPF_JA) code.k=positions[i+1+code.k]-positions[i]-1;
            else {
                code.jt=positions[i+1+code.jt]-positions[i]-1;
                code.jf=positions[i+1+code.jf]-positions[i]-1;
            }
        }
        out->code[positions[i]]=code;
    }
    out->count=used;
}
static int finish(const struct md_fd_filter_gates *gates,struct md_fd_filter_program *out,int all) {
    if (all) compact_all_descriptors(out);
    unsigned count=out->count,actions[3],targets[3],used=0;
    /* Resolve policy first. Unrelated syscall numbers return ALLOW without an
     * IP/argument load, preserving the kernel's seccomp allow cache. Only the
     * selected TRACE decisions need the exact internal-gate exemptions. */
    for (unsigned i=0;i<count;++i) {
        struct sock_filter *insn=&out->code[i];
        if (insn->code!=(BPF_RET|BPF_K) || (insn->k&SECCOMP_RET_ACTION_FULL)!=SECCOMP_RET_TRACE) continue;
        unsigned action=insn->k,j=0;
        while (j<used && actions[j]!=action) ++j;
        if (j==used) { if (used==3) return -E2BIG; actions[used++]=action; }
    }
    if (!used) return 0;
    unsigned extra=MD_FD_FILTER_EXEMPTIONS+(used>1 ? 4*used-1 : 0);
    if (out->count+extra>MD_FD_FILTER_INSTRUCTIONS) return -E2BIG;
    if (used==1) {
        targets[0]=out->count;
        exemptions(gates,out);
        out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,actions[0]);
    } else {
        /* X carries the selected action through one shared gate matcher.
         * Ordinary ALLOW exits never read IP or enter this tail. */
        for (unsigned i=0;i<used;++i) {
            targets[i]=out->count;
            out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_LDX|BPF_IMM,actions[i]);
            out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_JMP|BPF_JA,2*(used-i-1));
        }
        exemptions(gates,out);
        out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_MISC|BPF_TXA,0);
        for (unsigned i=0;i<used;++i) {
            if (i+1<used) out->code[out->count++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,actions[i],0,1);
            out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,actions[i]);
        }
    }
    for (unsigned i=0;i<count;++i) {
        struct sock_filter *insn=&out->code[i];
        if (insn->code!=(BPF_RET|BPF_K) || (insn->k&SECCOMP_RET_ACTION_FULL)!=SECCOMP_RET_TRACE) continue;
        unsigned j=0;
        while (actions[j]!=insn->k) ++j;
        *insn=(struct sock_filter)BPF_STMT(BPF_JMP|BPF_JA,targets[j]-i-1);
    }
    return 0;
}
struct descriptor_operation { unsigned nr,arguments,action; };
static int descriptor_operations(struct md_fd_filter_program *out,int fd,
        const struct descriptor_operation *operations,unsigned count) {
    enum { MAX_OPERATIONS=32 };
    unsigned targets[MAX_OPERATIONS];
    if (count>MAX_OPERATIONS || out->count+count+10>MD_FD_FILTER_INSTRUCTIONS)
        return -E2BIG;
    unsigned first=out->count;
    for (unsigned i=0;i<count;++i)
        out->code[out->count++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,operations[i].nr,0,0);
    const struct sock_filter duplicates[]={
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_dup,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_dup3,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD_CLOEXEC,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
    for (unsigned i=0;i<sizeof(duplicates)/sizeof(*duplicates);++i) out->code[out->count++]=duplicates[i];
    /* Syscall dispatch retains nr in A. Share FD tests by argument set and
     * result, so two-descriptor calls still match either input or output. */
    for (unsigned i=0;i<count;++i) {
        const struct descriptor_operation *op=operations+i;
        unsigned prior=0;
        while (prior<i && (operations[prior].action!=op->action
                || (fd!=-1 && operations[prior].arguments!=op->arguments))) ++prior;
        if (prior<i) targets[i]=targets[prior];
        else {
            targets[i]=out->count;
            unsigned tests=0,seen=0;
            for (unsigned args=op->arguments;args;args&=args-1) ++tests;
            if (out->count+(fd==-1 ? 1 : 3*tests+2)>MD_FD_FILTER_INSTRUCTIONS) return -E2BIG;
            if (fd!=-1) for (unsigned arg=0;arg<6;++arg) if (op->arguments&(1u<<arg)) {
                out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
                    offsetof(struct seccomp_data,args)+arg*sizeof(uint64_t));
                out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_ALU|BPF_AND|BPF_K,MD_FD_SELECTOR_MASK);
                out->code[out->count++]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,
                    (unsigned)fd&MD_FD_SELECTOR_MASK,3*(tests-++seen)+1,0);
            }
            if (fd!=-1) out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW);
            out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|op->action);
        }
        unsigned offset=targets[i]-(first+i)-1;
        if (offset>UINT8_MAX) return -E2BIG;
        out->code[first+i].jt=offset;
    }
    return 0;
}

int md_fd_filter_build(enum md_fd_selector_kind kind,int fd,
        const struct md_fd_filter_gates *gates,struct md_fd_filter_program *out) {
    if (!out) return -EINVAL;
    out->count=0;
    if (!gates || fd< -1 || kind<0 || kind>=MD_FD_SELECTOR_KINDS) return -EINVAL;
    unsigned mask=fd==-1 ? 0 : MD_FD_SELECTOR_MASK;
    out->code[out->count++]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr));
#define ADAPT(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_##n,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_DISPATCH),
#define COPY_PROGRAM(...) do { \
    struct sock_filter code[]={__VA_ARGS__}; \
    _Static_assert(1+3*MD_FD_FILTER_EXEMPTIONS+sizeof(code)/sizeof(*code)<=MD_FD_FILTER_INSTRUCTIONS,"FD filter capacity"); \
    for (unsigned i=0;i<sizeof(code)/sizeof(*code);++i) out->code[out->count++]=code[i]; \
    return finish(gates,out,fd==-1); \
} while (0)
#define OP(n,args,action) {SYS_##n,args,MD_INTERCEPT_##action}
#define SELECT_OPERATIONS(...) do { \
    const struct descriptor_operation operations[]={__VA_ARGS__}; \
    int error=descriptor_operations(out,fd,operations,sizeof(operations)/sizeof(*operations)); \
    return error ? error : finish(gates,out,fd==-1); \
} while (0)
    if (kind==MD_FD_SELECTOR_WATCH || kind==MD_FD_SELECTOR_IOCTL) {
        const struct sock_filter prefix[]={
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_K|(kind==MD_FD_SELECTOR_WATCH ? BPF_JEQ : BPF_JSET),
            kind==MD_FD_SELECTOR_WATCH ? FIONREAD : MD_IOCTL_DIRECTION_MASK,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr))};
        for (unsigned i=0;i<sizeof(prefix)/sizeof(*prefix);++i) out->code[out->count++]=prefix[i];
        if (kind==MD_FD_SELECTOR_IOCTL) SELECT_OPERATIONS(OP(ioctl,1,PROC));
        SELECT_OPERATIONS(OP(read,1,WATCH),OP(readv,1,WATCH),OP(ioctl,1,WATCH),
            OP(splice,1,WATCH),OP(tee,1,WATCH),OP(sendfile,2,WATCH));
    }
    if (kind==MD_FD_SELECTOR_PROC) {
        const struct sock_filter prefix[]={
        /* CLOEXEC belongs to the descriptor table, not its provider. The base
         * filter observes the native mutation and publishes its exact result. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,FIOCLEX,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,FIONCLEX,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        /* Controlled shared mappings may have a writable provider backing.
         * Only tasks admitting controlled descriptors acquire this check. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,PROT_WRITE,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_MEMORY),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        /* Anonymous mmap ignores the FD, including adapter stack allocation. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[3])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,MAP_ANONYMOUS,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,10),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFL,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFL,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GET_SEALS,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_ADD_SEALS,0,5),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K,mask),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)fd&mask,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE|MD_INTERCEPT_PROC),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        };
        for (unsigned i=0;i<sizeof(prefix)/sizeof(*prefix);++i) out->code[out->count++]=prefix[i];
#define FILE_OP(n) OP(n,1,PROC)
        SELECT_OPERATIONS(
            FILE_OP(read),FILE_OP(write),FILE_OP(readv),FILE_OP(writev),
            OP(sendto,1,DISPATCH),OP(recvfrom,1,DISPATCH),
            FILE_OP(pread64),FILE_OP(pwrite64),FILE_OP(preadv),FILE_OP(pwritev),
            FILE_OP(preadv2),FILE_OP(pwritev2),FILE_OP(lseek),FILE_OP(ioctl),
            OP(mmap,1u<<4,PROC),FILE_OP(getdents64),FILE_OP(fstatfs),
            FILE_OP(ftruncate),FILE_OP(fsync),FILE_OP(fdatasync),
            OP(sendfile,3,PROC),OP(splice,5,PROC),OP(tee,3,PROC),OP(copy_file_range,5,PROC));
#undef FILE_OP
    }
    if (kind==MD_FD_SELECTOR_EPOLL_TARGET) SELECT_OPERATIONS(OP(epoll_ctl,4,READINESS));
    if (kind==MD_FD_SELECTOR_EPOLL) SELECT_OPERATIONS(OP(epoll_ctl,1,READINESS),
        OP(epoll_pwait,1,READINESS),OP(epoll_pwait2,1,READINESS));
    if (kind==MD_FD_SELECTOR_POLL) COPY_PROGRAM(
        ADAPT(ppoll) ADAPT(pselect6)
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    );
    return -EINVAL;
#undef COPY_PROGRAM
#undef SELECT_OPERATIONS
#undef OP
#undef ADAPT
}
