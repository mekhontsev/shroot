#define _GNU_SOURCE
#include "shroot.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void handler(int signal) { (void)signal; }
static struct shroot_result wait_job(shroot_job *job) {
    struct pollfd fd = {shroot_job_fd(job), POLLIN, 0};
    assert(fd.fd >= 0 && shroot_job_pid(job) > 0);
    assert(shroot_job_close(job) == -EBUSY);
    /* EVENT_WAIT: exact child's exit; a stalled fixture fails after five seconds. */
    assert(poll(&fd, 1, 5000) == 1 && (fd.revents & POLLIN));
    struct shroot_result result, again;
    assert(!shroot_job_wait(job, 1, &result));
    assert(!shroot_job_wait(job, 1, &again));
    assert(result.error == again.error && result.exit_code == again.exit_code && result.signal == again.signal);
    assert(!shroot_job_cancel(job)); assert(!shroot_job_close(job)); return result;
}
static void modes(shroot_context *context) {
    const char *names[] = {"missing", "invalid", "duplicate", "incomplete", "error"};
    for (size_t i = 0; i < sizeof(names)/sizeof(*names); ++i) {
        char mode[64]; snprintf(mode, sizeof(mode), "SHROOT_TEST_MODE=%s", names[i]);
        char *env[] = {mode, NULL};
        struct shroot_io io = {-1, -1, -1, env};
        shroot_job *job = NULL;
        assert(!shroot_storage_format(context, &io, &job));
        struct shroot_result result = wait_job(job);
        assert(result.error == (i == 4 ? -EBUSY : -EPROTO));
    }
}
static void arguments(shroot_context *context, const char *directory) {
    shroot_store *store = NULL;
    assert(!shroot_store_open(context, directory, &store));
    FILE *file = tmpfile(); assert(file);
    char *env[] = {"SHROOT_TEST_MODE=args", NULL};
    struct shroot_io io = {-1, fileno(file), -1, env};
    const char *argv[] = {"/bin/program", "spaces ' ; $(false)", "", NULL};
    const char *overrides[] = {"VALUE=quotes ' \" $()", NULL};
    struct shroot_bind bind = {SHROOT_BIND_READONLY, "/host a", "/guest a"};
    struct shroot_socket_route route = {SHROOT_SOCKET_RESOURCE_ABSTRACT, "source", "target"};
    struct shroot_launch_options options = {.kind=SHROOT_EXEC, .arguments=argv, .environment=overrides,
        .binds=&bind, .bind_count=1, .routes=&route, .route_count=1};
    shroot_job *job = NULL;
    assert(!shroot_launch(store, &options, &io, &job));
    assert(!wait_job(job).error);
    rewind(file); char output[4096] = {0}; assert(fread(output, 1, sizeof(output)-1, file) > 0);
    assert(strstr(output, "--env\nVALUE=quotes ' \" $()\n"));
    assert(strstr(output, "--bind-ro\n/host a\n/guest a\n"));
    assert(strstr(output, "--socket-resource-abstract\nsource\ntarget\n"));
    assert(strstr(output, "--\n/bin/program\nspaces ' ; $(false)\n\n"));
    fclose(file);
    options.flags = 16;
    assert(shroot_launch(store, &options, &io, &job) == -EINVAL && !job);
    options.flags = 0;
    char *launch_env[] = {"SHROOT_TEST_MODE=launch", NULL};
    io = (struct shroot_io){-1, -1, -1, launch_env};
    assert(!shroot_launch(store, &options, &io, &job));
    struct shroot_result result = wait_job(job);
    assert(!result.error && !result.signal && result.exit_code == 42);
    shroot_library *library=NULL;
    assert(!shroot_library_open(context,"/missing/catalog with spaces",&library));
    file=tmpfile(); assert(file);
    io=(struct shroot_io){-1,fileno(file),-1,env};
    struct shroot_install_options install={SHROOT_SOURCE_ROOTFS,"/input ' literal","named","nameserver 192.0.2.1\n"};
    assert(!shroot_environment_install(library,&install,&io,&job));
    assert(!wait_job(job).error);
    rewind(file); memset(output,0,sizeof(output)); assert(fread(output,1,sizeof(output)-1,file)>0);
    assert(strstr(output,"library\n/missing/catalog with spaces\ninstall\nrootfs\n/input ' literal\nnamed\n"));
    assert(strstr(output,"--resolver\nnameserver 192.0.2.1\n"));
    fclose(file);
    io=(struct shroot_io){-1,-1,-1,launch_env};
    assert(!shroot_environment_launch(library,"named",&options,&io,&job));
    result=wait_job(job);
    assert(!result.error && result.exit_code==42 && !result.signal);
    shroot_library_close(library);
    shroot_store_close(store);
}
struct wait_context { shroot_job *job; struct shroot_result result; int error; };
static void *blocking_wait(void *opaque) {
    struct wait_context *context = opaque;
    context->error = shroot_job_wait(context->job, 0, &context->result);
    return NULL;
}
static void cancellation(shroot_context *context) {
    int ready[2]; assert(!pipe2(ready, O_CLOEXEC));
    char *env[] = {"SHROOT_TEST_MODE=wait", NULL};
    struct shroot_io io = {-1, ready[1], -1, env};
    shroot_job *job = NULL;
    assert(!shroot_storage_format(context, &io, &job));
    close(ready[1]);
    struct pollfd fd = {ready[0], POLLIN, 0};
    /* EVENT_WAIT: worker fixture explicitly announces entry before cancellation. */
    assert(poll(&fd, 1, 5000) == 1);
    char data[6]; assert(read(ready[0], data, 6) == 6); close(ready[0]);
    struct shroot_result result;
    assert(shroot_job_wait(job, 1, &result) == -EAGAIN);
    struct wait_context waiting = {.job=job};
    pthread_t waiter; assert(!pthread_create(&waiter, NULL, blocking_wait, &waiting));
    assert(!shroot_job_cancel(job));
    assert(!pthread_join(waiter, NULL) && !waiting.error);
    result = waiting.result; assert(!shroot_job_close(job));
    assert(!result.error && result.signal == SIGTERM);
}
static void *concurrent(void *value) {
    shroot_context *context = value;
    struct shroot_io io = {-1, -1, -1, NULL};
    for (int i = 0; i < 12; ++i) {
        shroot_job *job = NULL;
        assert(!shroot_storage_format(context, &io, &job));
        struct shroot_result result = wait_job(job);
        assert(!result.error && !result.exit_code && !result.signal);
    }
    return NULL;
}
static void early_cancel(shroot_context *context) {
    for (int i = 0; i < 16; ++i) {
        struct shroot_io io = {-1, -1, -1, NULL};
        shroot_job *job = NULL;
        assert(!shroot_storage_format(context, &io, &job));
        assert(!shroot_job_cancel(job));
        struct shroot_result result = wait_job(job);
        if (result.error || (result.signal && result.signal != SIGTERM))
            fprintf(stderr, "early cancel: error=%d exit=%d signal=%d\n", result.error, result.exit_code, result.signal);
        assert(!result.error && (!result.signal || result.signal == SIGTERM));
    }
    struct sigaction ignored = {.sa_handler=SIG_IGN}, previous;
    sigemptyset(&ignored.sa_mask);
    assert(!sigaction(SIGCHLD, &ignored, &previous));
    shroot_job *job = NULL;
    assert(shroot_storage_format(context, NULL, &job) == -ENOTSUP && !job);
    assert(!sigaction(SIGCHLD, &previous, NULL));
}
static void closed_stdio(shroot_context *context) {
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(0); close(1); close(2);
        shroot_job *job = NULL;
        assert(shroot_storage_format(context, NULL, &job) == -EBADF && !job);
        struct shroot_io io = {-1, -1, -1, NULL};
        assert(!shroot_storage_format(context, &io, &job));
        struct shroot_result result = wait_job(job);
        _exit(result.error || result.exit_code || result.signal ? 1 : 0);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}
int main(int argc, char **argv) {
    assert(argc == 2);
    shroot_context *context = NULL;
    assert(!shroot_context_open(argv[1], &context));
    assert(shroot_version() && *shroot_version());
    struct sigaction before = {.sa_handler=handler}, after;
    sigemptyset(&before.sa_mask); assert(!sigaction(SIGUSR1, &before, NULL));
    sigset_t original, mask, current;
    sigemptyset(&mask); sigaddset(&mask, SIGUSR2);
    assert(!pthread_sigmask(SIG_BLOCK, &mask, &original));
    mode_t previous = umask(0077);
    char *cwd = getcwd(NULL, 0); assert(cwd);
    assert(!setenv("SHROOT_CLIENT_PARENT", "retained", 1));
    modes(context); arguments(context, argv[1]); cancellation(context); early_cancel(context);
    closed_stdio(context);
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, concurrent, context));
    for (int i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(!sigaction(SIGUSR1, NULL, &after) && after.sa_handler == handler);
    assert(!pthread_sigmask(SIG_BLOCK, NULL, &current) && sigismember(&current, SIGUSR2));
    assert(!pthread_sigmask(SIG_SETMASK, &original, NULL));
    assert(umask(previous) == 0077);
    char *now = getcwd(NULL, 0); assert(now && !strcmp(cwd, now)); free(now); free(cwd);
    assert(!strcmp(getenv("SHROOT_CLIENT_PARENT"), "retained"));
    shroot_context_close(context);
    puts("PASS libshroot: protocol, literal arguments, cancellation, concurrent callers and host process isolation");
    return 0;
}
