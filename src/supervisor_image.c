#define _GNU_SOURCE
#include "supervisor_image.h"
#include "bootstrap_entry.h"
#include "elf.h"
#include "supervisor_internal.h"
#include "supervisor_execution.h"
#include "supervisor_task.h"
#include "signal_protocol.h"
#include "raw.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct image_segment { uintptr_t offset; size_t size; int entry; };
static struct {
    uintptr_t entry,base;
    size_t size,count,alignment;
    struct image_segment *segments;
} bootstrap_layout;

struct bootstrap_move {
    struct user_pt_regs initial;
    uintptr_t source,allocation;
    size_t prefix,suffix;
    uint64_t mask;
    size_t step;
    long expected;
    int entered,code_moved,number,initial_placement;
};

static int segment_order(const void *left,const void *right) {
    const struct image_segment *a=left,*b=right;
    return a->entry-b->entry;
}

int image_layout_prepare(const char *path) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) return -errno;
    struct md_elf_layout image;
    int error=md_elf_layout_read(fd,1,&image);
    close(fd);
    if (error) return error;
    if (image.low) return -ENOEXEC;
    struct image_segment *segments=calloc((size_t)image.header.e_phnum*2,sizeof(*segments));
    if (!segments) return -ENOMEM;
    size_t count=0;
    int entry_found=0;
    for (unsigned i=0;i<image.header.e_phnum;++i) {
        const Elf64_Phdr *p=image.segments+i;
        if (p->p_type!=PT_LOAD || !p->p_memsz) continue;
        uintptr_t low=p->p_vaddr&~(md_page_size-1);
        uintptr_t file=(p->p_vaddr+p->p_filesz+md_page_size-1)&~(md_page_size-1);
        uintptr_t high=(p->p_vaddr+p->p_memsz+md_page_size-1)&~(md_page_size-1);
        int entry=(p->p_flags&PF_X) && image.header.e_entry>=p->p_vaddr
            && image.header.e_entry-p->p_vaddr<p->p_filesz;
        if (entry && p->p_filesz-(image.header.e_entry-p->p_vaddr)<MD_BOOTSTRAP_ENTRY_BYTES) {
            error=-ENOEXEC; break;
        }
        entry_found|=entry;
        if (p->p_filesz) segments[count++]=(struct image_segment){low,file-low,entry};
        else file=low;
        if (high>file) segments[count++]=(struct image_segment){file,high-file,0};
    }
    if (!error && !entry_found) error=-ENOEXEC;
    if (error) { free(segments); return error; }
    qsort(segments,count,sizeof(*segments),segment_order);
    bootstrap_layout.entry=image.header.e_entry; bootstrap_layout.size=image.high;
    bootstrap_layout.alignment=image.alignment;
    bootstrap_layout.count=count; bootstrap_layout.segments=segments;
    return 0;
}

void image_layout_release(void) {
    free(bootstrap_layout.segments);
    memset(&bootstrap_layout,0,sizeof(bootstrap_layout));
}

void image_layout_discard(struct thread *t) {
    free(t->bootstrap_move); t->bootstrap_move=NULL;
}

static void image_layout_resume(struct thread *t) {
    if (!tracee_request(t,PTRACE_SYSCALL,NULL,NULL,"bootstrap-placement")) return;
    t->kernel_resume=PTRACE_SYSCALL; t->kernel_stopped=0;
}

static void image_layout_failed(struct thread *t,const char *reason) {
    fprintf(stderr,"Shroot: bootstrap placement failed: %s\n",reason);
    image_layout_discard(t);
    /* A partially moved exec image cannot return to user code. Retain task
     * custody through its normal exit event and reaping, never leave a stop. */
    kill(t->pid,SIGKILL);
    if (tracee_request(t,PTRACE_CONT,NULL,NULL,"bootstrap-placement-failed")) {
        t->kernel_resume=PTRACE_CONT; t->kernel_stopped=0;
    }
}

int image_layout_begin(struct thread *t) {
    if (!bootstrap_layout.segments) return 0;
    struct user_pt_regs regs;
    if (!registers(t->pid,&regs)) return 1;
    uintptr_t source=regs.pc-bootstrap_layout.entry;
    if (source==bootstrap_layout.base) return 0;
    CHECK(!t->bootstrap_move);
    struct bootstrap_move *move=calloc(1,sizeof(*move)); CHECK(move);
    move->initial=regs; move->source=source;
    move->initial_placement=!bootstrap_layout.base;
    t->bootstrap_move=move;
    if (!save_signal_mask(t,&move->mask,"bootstrap-placement-mask")) return 1;
    uint64_t mask=md_signal_blockable_mask();
    if (!signal_mask(t,mask,"bootstrap-placement-mask")) return 1;
    t->phase=IMAGE_RELOCATING;
    image_layout_resume(t);
    return 1;
}

static int image_layout_call(struct thread *t,struct user_pt_regs *regs) {
    struct bootstrap_move *move=t->bootstrap_move;
    long number;
    memset(regs->regs,0,6*sizeof(*regs->regs));
    if (!move->step) {
        number=SYS_mmap;
        /* Keep the 32-bit guest range free without splitting the large hole
         * below the native PIE heap. Preserve ASLR bits from the source; the
         * first mmap is only a hint, including for nested launches. */
        const uintptr_t low_va_end=UINT64_C(1)<<32;
        regs->regs[0]=move->initial_placement
            ? (low_va_end+(move->source&(low_va_end-1)))&~(bootstrap_layout.alignment-1)
            : bootstrap_layout.base;
        regs->regs[1]=bootstrap_layout.size
            +(move->initial_placement ? bootstrap_layout.alignment-md_page_size : 0);
        regs->regs[2]=PROT_NONE;
        regs->regs[3]=MAP_PRIVATE|MAP_ANONYMOUS
            |(move->initial_placement ? 0 : MAP_FIXED_NOREPLACE);
        regs->regs[4]=(uint64_t)-1;
        move->expected=bootstrap_layout.base;
    } else if (move->step<=bootstrap_layout.count) {
        const struct image_segment *segment=bootstrap_layout.segments+move->step-1;
        number=SYS_mremap;
        regs->regs[0]=move->source+segment->offset;
        regs->regs[1]=regs->regs[2]=segment->size;
        regs->regs[3]=MREMAP_MAYMOVE|MREMAP_FIXED;
        regs->regs[4]=bootstrap_layout.base+segment->offset;
        move->expected=regs->regs[4];
    } else if (move->step==bootstrap_layout.count+1) {
        number=SYS_munmap;
        regs->regs[0]=move->source;
        regs->regs[1]=bootstrap_layout.size;
        move->expected=0;
    } else {
        number=SYS_munmap;
        int prefix=move->step==bootstrap_layout.count+2;
        regs->regs[0]=prefix ? move->allocation : bootstrap_layout.base+bootstrap_layout.size;
        regs->regs[1]=prefix ? move->prefix : move->suffix;
        move->expected=0;
    }
    /* Kernel policy survives exec. The new image's temporary SVC enters with
     * the established service identity; no guest instruction has run yet. */
    if (!move->initial_placement) regs->pc=abi.task_return;
    regs->regs[8]=number;
    move->number=(int)number;
    int nr=(int)number;
    struct iovec io={&nr,sizeof(nr)};
    return set_registers(t->pid,regs)
        && tracee_request(t,PTRACE_SETREGSET,(void *)NT_ARM_SYSTEM_CALL,&io,"bootstrap-placement-call");
}

int image_layout_event(struct thread *t,int status) {
    struct bootstrap_move *move=t->bootstrap_move;
    if (!move) return 0;
    if (WIFEXITED(status) || WIFSIGNALED(status)) { image_layout_discard(t); return 0; }
    if (!WIFSTOPPED(status)) return 0;
    unsigned event=(unsigned)status>>16;
    if (event==PTRACE_EVENT_SECCOMP) {
        struct ptrace_syscall_info info={0};
        if (!tracee_request(t,PTRACE_GET_SYSCALL_INFO,(void *)sizeof(info),&info,
                "bootstrap-placement-policy")) return 1;
        if (!move->entered || info.op!=PTRACE_SYSCALL_INFO_SECCOMP
                || info.instruction_pointer!=abi.task_return
                || info.seccomp.nr!=(unsigned)move->number
                || info.seccomp.ret_data!=MD_INTERCEPT_TASK) {
            image_layout_failed(t,"unexpected policy boundary"); return 1;
        }
        image_layout_resume(t); return 1;
    }
    if (event || WSTOPSIG(status)!=(SIGTRAP|0x80)) return 0;
    struct ptrace_syscall_info info;
    struct user_pt_regs regs;
    if (!tracee_request(t,PTRACE_GET_SYSCALL_INFO,(void *)sizeof(info),&info,"bootstrap-placement-boundary")
            || !registers(t->pid,&regs)) return 1;
    if (info.op==PTRACE_SYSCALL_INFO_ENTRY) {
        uintptr_t source=move->code_moved ? bootstrap_layout.base : move->source;
        if (move->entered || info.entry.nr!=SYS_gettid
                || info.instruction_pointer!=source+bootstrap_layout.entry+MD_BOOTSTRAP_ENTRY_BYTES) {
            image_layout_failed(t,"unexpected syscall entry"); return 1;
        }
        if (!image_layout_call(t,&regs)) return 1;
        move->entered=1;
        image_layout_resume(t); return 1;
    }
    /* PTRACE_EVENT_EXEC precedes the completed execve's syscall-exit stop. */
    if (info.op==PTRACE_SYSCALL_INFO_EXIT && !move->entered && !move->step) {
        image_layout_resume(t); return 1;
    }
    if (info.op!=PTRACE_SYSCALL_INFO_EXIT || !move->entered) {
        image_layout_failed(t,"unexpected syscall completion"); return 1;
    }
    if (!move->step && move->initial_placement && (long)regs.regs[0]>0) {
        move->allocation=regs.regs[0];
        move->prefix=(-move->allocation)&(bootstrap_layout.alignment-1);
        move->suffix=bootstrap_layout.alignment-md_page_size-move->prefix;
        bootstrap_layout.base=move->allocation+move->prefix;
        move->expected=regs.regs[0];
    }
    if ((long)regs.regs[0]!=move->expected) {
        fprintf(stderr,"Shroot: bootstrap placement step=%zu result=%ld expected=%ld source=%#lx size=%zu\n",
            move->step,(long)regs.regs[0],move->expected,(unsigned long)move->source,bootstrap_layout.size);
        image_layout_failed(t,"mapping operation rejected"); return 1;
    }
    if (move->step && move->step<=bootstrap_layout.count
            && bootstrap_layout.segments[move->step-1].entry) move->code_moved=1;
    ++move->step;
    if (move->step==bootstrap_layout.count+2 && !move->prefix) ++move->step;
    if (move->step==bootstrap_layout.count+3 && !move->suffix) ++move->step;
    if (move->step<=bootstrap_layout.count+3) {
        regs=move->initial;
        regs.pc=(move->code_moved ? bootstrap_layout.base : move->source)+bootstrap_layout.entry;
        move->entered=0;
        if (set_registers(t->pid,&regs)) image_layout_resume(t);
        return 1;
    }
    regs=move->initial;
    regs.pc=bootstrap_layout.base+bootstrap_layout.entry+MD_BOOTSTRAP_ENTRY_BYTES;
    uint64_t mask=move->mask;
    image_layout_discard(t);
    if (!set_registers(t->pid,&regs) || !signal_mask(t,mask,"bootstrap-placement-restored")) return 1;
    t->phase=IDLE;
    task_exec_ready(t);
    return 1;
}
