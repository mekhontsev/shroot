#define _GNU_SOURCE
#include "shroot.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

static struct shroot_result wait_job(shroot_job *job) {
    struct pollfd fd = {shroot_job_fd(job), POLLIN, 0};
    /* EVENT_WAIT: real operation completion, with a fixture failure bound. */
    assert(poll(&fd, 1, 30000) == 1 && (fd.revents & POLLIN));
    struct shroot_result result;
    assert(!shroot_job_wait(job, 0, &result));
    assert(!shroot_job_close(job)); return result;
}
static void success(shroot_job *job) {
    struct shroot_result result = wait_job(job);
    if (result.error || result.exit_code || result.signal)
        fprintf(stderr, "operation: error=%d exit=%d signal=%d\n", result.error, result.exit_code, result.signal);
    assert(!result.error && !result.exit_code && !result.signal);
}
static void execute(shroot_store *store, const char *argument, int expected) {
    const char *argv[] = {"/bin/client-guest", argument, NULL};
    const char *env[] = {"LIBSHROOT_TEST=retained ' value", NULL};
    struct shroot_launch_options options = {.kind=SHROOT_EXEC, .arguments=argv, .environment=env};
    shroot_job *job = NULL;
    assert(!shroot_launch(store, &options, NULL, &job));
    struct shroot_result result = wait_job(job);
    if (result.error || result.exit_code != expected || result.signal)
        fprintf(stderr, "guest: error=%d exit=%d signal=%d\n", result.error, result.exit_code, result.signal);
    assert(!result.error && result.exit_code == expected && !result.signal);
}
static void cancellation(shroot_store *store) {
    int ready[2]; assert(!pipe2(ready, O_CLOEXEC));
    int leases[2][2];
    for (int i = 0; i < 2; ++i) assert(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, leases[i]));
    int owners[] = {leases[0][1], leases[1][1]};
    const char *argv[] = {"/bin/client-guest", "hold-owner", NULL};
    struct shroot_launch_options options = {.kind=SHROOT_EXEC, .arguments=argv, .owner_fds=owners, .owner_fd_count=2};
    struct shroot_io io = {-1, ready[1], 2, NULL};
    shroot_job *job = NULL;
    assert(!shroot_launch(store, &options, &io, &job));
    for (int i = 0; i < 2; ++i) {
        assert(fcntl(owners[i], F_GETFD) == FD_CLOEXEC);
        close(owners[i]);
    }
    close(ready[1]);
    struct pollfd fd = {ready[0], POLLIN, 0};
    /* EVENT_WAIT: guest has entered its blocking work before cancellation. */
    assert(poll(&fd, 1, 30000) == 1 && (fd.revents & POLLIN));
    char data[6]; assert(read(ready[0], data, sizeof(data)) == sizeof(data));
    for (int i = 0; i < 2; ++i) {
        struct pollfd lease = {leases[i][0], POLLIN, 0};
        assert(poll(&lease, 1, 0) == 0);
    }
    assert(!shroot_job_cancel(job));
    struct shroot_result result = wait_job(job);
    if (result.error || (result.exit_code != 128 + SIGTERM && result.signal != SIGTERM))
        fprintf(stderr, "cancellation: error=%d exit=%d signal=%d\n", result.error, result.exit_code, result.signal);
    assert(!result.error && (result.exit_code == 128 + SIGTERM || result.signal == SIGTERM));
    fd.revents = 0;
    /* EVENT_WAIT: no descendant retains the output pipe after tree cleanup. */
    assert(poll(&fd, 1, 5000) == 1 && (fd.revents & POLLHUP));
    close(ready[0]);
    for (int i = 0; i < 2; ++i) {
        struct pollfd lease = {leases[i][0], POLLIN, 0};
        assert(poll(&lease, 1, 5000) == 1 && (lease.revents & POLLHUP));
        close(leases[i][0]);
    }
    puts("PASS owner FDs: caller flags retained, guest isolation, whole-tree custody and cancellation release");
}
int main(int argc, char **argv) {
    assert(argc == 4);
    shroot_context *context = NULL;
    assert(!shroot_context_open(argv[1], &context));
    char image[4096], first[4096], second[4096], restored[4096], backup[4096];
    assert(snprintf(image, sizeof(image), "%s/image ' literal", argv[3]) < (int)sizeof(image));
    assert(snprintf(first, sizeof(first), "%s/first", argv[3]) < (int)sizeof(first));
    assert(snprintf(second, sizeof(second), "%s/second", argv[3]) < (int)sizeof(second));
    assert(snprintf(restored, sizeof(restored), "%s/restored", argv[3]) < (int)sizeof(restored));
    assert(snprintf(backup, sizeof(backup), "%s/backup.tar.zst", argv[3]) < (int)sizeof(backup));
    mode_t old_mask = umask(0077);
    int leaked = open("/dev/null", O_RDONLY); assert(leaked >= 0);
    assert(dup2(leaked, 123) == 123); close(leaked);
    shroot_job *job = NULL, *other = NULL;
    assert(!shroot_import_archive(context, SHROOT_ROOTFS, argv[2], image, NULL, &job)); success(job);
    shroot_store *source = NULL, *a = NULL, *b = NULL, *copy = NULL;
    assert(!shroot_store_open(context, image, &source));
    assert(!shroot_clone(source, first, NULL, &job));
    assert(!shroot_clone(source, second, NULL, &other));
    success(job); success(other);
    assert(!shroot_store_open(context, first, &a));
    assert(!shroot_store_open(context, second, &b));
    execute(a, "spaces ' ; $(false)", 0);
    execute(b, "exit42", 42);
    const char *missing[] = {"/no-such-program", NULL};
    struct shroot_launch_options options = {.kind=SHROOT_EXEC, .arguments=missing};
    assert(!shroot_launch(a, &options, NULL, &job));
    struct shroot_result result = wait_job(job);
    /* Absolute commands are admitted by the existing runner; its conventional
     * 127 remains a runtime exit, not a fabricated successful launch. */
    assert(result.error == -ENOENT || (!result.error && result.exit_code == 127));
    cancellation(a);
    assert(!shroot_backup(a, backup, NULL, &job)); success(job);
    assert(!shroot_import_archive(context, SHROOT_BACKUP, backup, restored, NULL, &job)); success(job);
    assert(!shroot_store_open(context, restored, &copy));
    execute(copy, "spaces ' ; $(false)", 0);
    assert(!shroot_inspect(copy, NULL, &job)); success(job);
    assert(!shroot_import_archive(context, SHROOT_ROOTFS, "/nonexistent-shroot-test-archive", restored, NULL, &job));
    assert(wait_job(job).error == -ENOENT);
    assert(!shroot_remove(copy, NULL, &job)); success(job); shroot_store_close(copy);
    assert(!shroot_remove(b, NULL, &job)); success(job); shroot_store_close(b);
    assert(!shroot_remove(a, NULL, &job)); success(job); shroot_store_close(a);
    assert(!shroot_remove(source, NULL, &job)); success(job); shroot_store_close(source);
    assert(fcntl(123, F_GETFD) >= 0); close(123);
    assert(umask(old_mask) == 0077);
    shroot_context_close(context);
    puts("PASS libshroot runtime: import, concurrent clones, exec, cancellation, backup/restore and cleanup");
    return 0;
}
