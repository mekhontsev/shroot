#ifndef MD_TEST_FD_ACCOUNTING_H
#define MD_TEST_FD_ACCOUNTING_H

#include "fs_wire.h"
#include <assert.h>
#include <sys/eventfd.h>
#include <unistd.h>

/* A containing runtime may retain its per-table socket on first SCM_RIGHTS
 * receipt. Initialize that transport before measuring a component's FD balance. */
static inline void md_test_prepare_fd_transfer(void) {
    int fd=eventfd(0,EFD_CLOEXEC);
    assert(fd>=0 && md_fs_rights_transferable(&fd,1)==1 && !close(fd));
}
#endif
