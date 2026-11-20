#ifndef SHROOT_ATTACHMENT_OPTION_H
#define SHROOT_ATTACHMENT_OPTION_H
enum { MD_FS_ATTACHMENT_READONLY=1, MD_FS_ATTACHMENT_CREATE=2, MD_FS_ATTACHMENT_STORE=4, MD_FS_ATTACHMENT_FUSE=8 };
/* Order is the public shroot_bind_kind ABI. Freestanding runners share the
 * same spelling and flags without acquiring a libc dependency. */
static const struct { const char *option; unsigned flags; } md_attachment_options[]={
    {"--bind",0},{"--bind-ro",MD_FS_ATTACHMENT_READONLY},{"--bind-create",MD_FS_ATTACHMENT_CREATE},
    {"--bind-store-ro",MD_FS_ATTACHMENT_STORE|MD_FS_ATTACHMENT_READONLY},
    {"--bind-ro-create",MD_FS_ATTACHMENT_CREATE|MD_FS_ATTACHMENT_READONLY},
    {"--bind-fuse",MD_FS_ATTACHMENT_FUSE|MD_FS_ATTACHMENT_CREATE},
    {"--bind-fuse-ro",MD_FS_ATTACHMENT_FUSE|MD_FS_ATTACHMENT_CREATE|MD_FS_ATTACHMENT_READONLY}};
#define MD_ATTACHMENT_KINDS (sizeof(md_attachment_options)/sizeof(md_attachment_options[0]))
static inline int md_attachment_kind(const char *name) {
    for (unsigned i=0;i<MD_ATTACHMENT_KINDS;++i) {
        const char *a=name,*b=md_attachment_options[i].option;
        while (*a && *a==*b) { ++a; ++b; }
        if (*a==*b) return (int)i;
    }
    return -1;
}
static inline const char *md_attachment_option(unsigned flags) {
    for (unsigned i=0;i<MD_ATTACHMENT_KINDS;++i)
        if (md_attachment_options[i].flags==flags) return md_attachment_options[i].option;
    return (const char *)0;
}
#endif
