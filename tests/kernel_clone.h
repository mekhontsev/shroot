#ifndef MD_TEST_KERNEL_CLONE_H
#define MD_TEST_KERNEL_CLONE_H
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

/* Kernel-ABI fixtures deliberately create tasks without libc thread state.
 * musl's public clone wrapper rejects that contract before entering the kernel.
 * The child must not use pthread/TLS services or share libc state concurrently. */
extern long md_test_clone_kernel(int (*)(void *),void *,unsigned,void *,pid_t *,void *,pid_t *);
__asm__(".pushsection .text\n.local md_test_clone_kernel\n.type md_test_clone_kernel,%function\n"
    "md_test_clone_kernel:\nstp x19,x20,[sp,#-32]!\nstr x30,[sp,#16]\n"
    "mov x19,x0\nmov x20,x3\nmov w0,w2\nmov x2,x4\nmov x3,x5\nmov x4,x6\n"
    "and x1,x1,#-16\nmov x8,#220\nsvc #0\ncbnz x0,1f\n"
    "mov x0,x20\nblr x19\nmov x8,#93\nsvc #0\nbrk #0\n"
    "1: ldr x30,[sp,#16]\nldp x19,x20,[sp],#32\nret\n"
    ".size md_test_clone_kernel,.-md_test_clone_kernel\n.popsection\n");
static inline int md_test_clone(int (*entry)(void *),void *stack,int flags,void *argument,...) {
    pid_t *parent=NULL,*child=NULL; void *tls=NULL;
    if (flags&(CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|CLONE_SETTLS|CLONE_PIDFD)) {
        va_list args; va_start(args,argument);
        parent=va_arg(args,pid_t *); tls=va_arg(args,void *); child=va_arg(args,pid_t *);
        va_end(args);
    }
    if (!(flags&(CLONE_THREAD|CLONE_SETTLS|CLONE_CHILD_CLEARTID)))
        return clone(entry,stack,flags,argument,parent,tls,child);
    long result=md_test_clone_kernel(entry,stack,(unsigned)flags,argument,parent,tls,child);
    if (result<0) { errno=(int)-result; return -1; }
    return (int)result;
}
#endif
