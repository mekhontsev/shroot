#include "raw.h"
#include <elf.h>

/* The freestanding image has only link-time relative relocations. No libc,
 * global pointers or syscalls are needed before this entry completes. */
void md_boot_relocate(uintptr_t base,const Elf64_Dyn *dynamic,uintptr_t *stack) {
    const Elf64_Rela *rela=NULL;
    const uintptr_t *relr=NULL;
    size_t size=0,packed_size=0;
    for (const Elf64_Dyn *d=dynamic;d->d_tag;++d) {
        if (d->d_tag==DT_RELA) rela=(const void *)(base+d->d_un.d_ptr);
        if (d->d_tag==DT_RELASZ) size=d->d_un.d_val;
        /* Standard RELR and Android's original tags encode the same table. */
        if (d->d_tag==36 || d->d_tag==0x6fffe000) relr=(const void *)(base+d->d_un.d_ptr);
        if (d->d_tag==35 || d->d_tag==0x6fffe001) packed_size=d->d_un.d_val;
    }
    for (size_t i=0;i<size/sizeof(*rela);++i) {
        const Elf64_Rela *r=rela+i;
        if (ELF64_R_TYPE(r->r_info)!=R_AARCH64_RELATIVE) RAW1(exit_group,126);
        *(uintptr_t *)(base+r->r_offset)=base+r->r_addend;
    }
    uintptr_t *at=NULL;
    for (size_t i=0;i<packed_size/sizeof(*relr);++i) {
        uintptr_t value=relr[i];
        if (!(value&1)) { at=(void *)(base+value); *at+++=base; }
        else {
            for (unsigned bit=1;bit<64;++bit) if (value&(1UL<<bit)) at[bit-1]+=base;
            at+=63;
        }
    }
    /* The kernel describes the initial placement. Exec may have moved this
     * same image before its first instruction; keep its auxiliary view exact. */
    uintptr_t *environment=stack+stack[0]+2;
    while (*environment++) {}
    const Elf64_Ehdr *header=(const void *)base;
    for (Elf64_auxv_t *a=(void *)environment;a->a_type!=AT_NULL;++a) {
        if (a->a_type==AT_PHDR) a->a_un.a_val=base+header->e_phoff;
        if (a->a_type==AT_ENTRY) a->a_un.a_val=base+header->e_entry;
    }
}
