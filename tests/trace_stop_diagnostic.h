#ifndef SHROOT_TRACE_STOP_DIAGNOSTIC_H
#define SHROOT_TRACE_STOP_DIAGNOSTIC_H
#include <asm/ptrace.h>
#include <elf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

static inline void report_unexpected_stop(pid_t child,int status) {
    struct user_pt_regs regs={0};
    struct iovec buffer={&regs,sizeof(regs)};
    siginfo_t info={0};
    long signal_result=ptrace(PTRACE_GETSIGINFO,child,NULL,&info);
    long regs_result=ptrace(PTRACE_GETREGSET,child,(void *)NT_PRSTATUS,&buffer);
    fprintf(stderr,"unexpected stop signal=%d status=%#x siginfo=%ld code=%d address=%p"
        " regset=%ld pc=%#llx sp=%#llx lr=%#llx x8=%llu\n",
        WSTOPSIG(status),status,signal_result,info.si_code,info.si_addr,regs_result,
        (unsigned long long)regs.pc,(unsigned long long)regs.sp,
        (unsigned long long)regs.regs[30],(unsigned long long)regs.regs[8]);
    if (!regs_result && WSTOPSIG(status)==SIGSEGV) {
        char path[64],line[512];
        snprintf(path,sizeof(path),"/proc/%d/maps",child);
        FILE *maps=fopen(path,"r");
        if (!maps) return;
        while (fgets(line,sizeof(line),maps)) {
            unsigned long long begin,end;
            if (sscanf(line,"%llx-%llx",&begin,&end)==2
                    && ((regs.pc>=begin && regs.pc<end) || strstr(line,"[vdso]")))
                fputs(line,stderr);
        }
        fclose(maps);
    }
}
#endif
