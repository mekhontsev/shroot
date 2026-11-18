#ifndef MD_HOST_OPEN_H
#define MD_HOST_OPEN_H
#include <linux/openat2.h>
/* Captured local path/how, under the caller's native identity. Native openat2
 * stays first. The fallback never relaxes unsupported resolution constraints. */
long md_host_open_resolved(int,const char *,const struct open_how *);
/* Anonymous private backing, never later linked into a namespace. The caller
 * supplies an owned scratch directory; no process-global temporary path. */
long md_host_temporary(int,const char *,unsigned);
/* Kernel rename flags, including libcs without a renameat2 wrapper. */
long md_host_rename(int,const char *,int,const char *,unsigned);
/* Change the retained object, including O_PATH; never follow a retained symlink.
 * Baseline primitives also work when the host lacks fchmodat2/AT_EMPTY_PATH. */
long md_host_chmod_fd(int,unsigned);
#endif
