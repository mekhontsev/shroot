#ifndef SHROOT_TEST_FILTER_COUNT_H
#define SHROOT_TEST_FILTER_COUNT_H
#include <assert.h>
#include <sys/prctl.h>
#include <unistd.h>

/* The harness observes our task in its own procfs, outside the runtime under test. */
static int filters(void) {
    char comm[16]={0};
    int count = -1;
    assert(!prctl(PR_GET_NAME,comm));
    assert(write(STDIN_FILENO, comm, sizeof(comm)) == sizeof(comm));
    assert(read(STDIN_FILENO, &count, sizeof(count)) == sizeof(count));
    assert(count > 0);
    return count;
}
#endif
