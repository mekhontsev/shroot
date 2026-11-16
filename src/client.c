#define _GNU_SOURCE
#include "client_internal.h"
#include "client_protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
struct shroot_job {
    pid_t pid;
    int process, channel, launch;
    atomic_int finished;
    struct shroot_result result;
};

const char *shroot_version(void) { return SHROOT_VERSION; }
int shroot_context_open(const char *directory, shroot_context **out) {
    if (!out) return -EINVAL;
    *out = NULL;
    if (!directory || !*directory) return -EINVAL;
    char *canonical = realpath(directory, NULL);
    if (!canonical) return -errno;
    shroot_context *context = calloc(1, sizeof(*context));
    int r = context ? 0 : -ENOMEM;
    if (!r && asprintf(&context->worker, "%s/libmagicdesk_guest_image.so", canonical) < 0) r = -ENOMEM;
    free(canonical);
    struct stat st;
    if (!r && stat(context->worker, &st)) r = -errno;
    if (!r && (!S_ISREG(st.st_mode) || (st.st_mode & (S_ISUID | S_ISGID)))) r = -EACCES;
    if (!r && access(context->worker, X_OK)) r = -errno;
    if (r) { shroot_context_close(context); return r; }
    *out = context; return 0;
}
void shroot_context_close(shroot_context *context) {
    if (context) { free(context->worker); free(context); }
}
int shroot_store_open(shroot_context *context, const char *path, shroot_store **out) {
    if (!out) return -EINVAL;
    *out = NULL;
    if (!context || !path || !*path) return -EINVAL;
    char *canonical = realpath(path, NULL);
    if (!canonical) return -errno;
    struct stat st;
    int r = stat(canonical, &st) ? -errno : !S_ISDIR(st.st_mode) ? -ENOTDIR : 0;
    shroot_store *store = r ? NULL : calloc(1, sizeof(*store));
    if (!r && !store) r = -ENOMEM;
    if (r) { free(canonical); return r; }
    store->context = context; store->path = canonical; *out = store; return 0;
}
void shroot_store_close(shroot_store *store) {
    if (store) { free(store->path); free(store); }
}
int shroot_library_open(shroot_context *context,const char *path,shroot_library **out) {
    if (!out) return -EINVAL;
    *out=NULL;
    if (!context || !path || !*path) return -EINVAL;
    shroot_library *library=calloc(1,sizeof(*library));
    if (!library) return -ENOMEM;
    int r=0;
    if (*path=='/') library->path=strdup(path);
    else {
        char *cwd=getcwd(NULL,0);
        if (!cwd) r=-errno;
        else if (asprintf(&library->path,"%s/%s",cwd,path)<0) r=-ENOMEM;
        free(cwd);
    }
    if (!r && !library->path) r=-ENOMEM;
    if (r) { shroot_library_close(library); return r; }
    library->context=context; *out=library; return 0;
}
void shroot_library_close(shroot_library *library) {
    if (library) { free(library->path); free(library); }
}
void shroot_argument(struct shroot_arguments *args, const char *value) {
    if (args->error) return;
    if (!value) { args->error = -EINVAL; return; }
    if (args->count + 1 >= args->capacity) {
        size_t capacity = args->capacity ? args->capacity * 2 : 32;
        if (capacity <= args->capacity || capacity > SIZE_MAX / sizeof(*args->values)) {
            args->error = -E2BIG; return;
        }
        const char **values = realloc(args->values, capacity * sizeof(*values));
        if (!values) { args->error = -ENOMEM; return; }
        args->values = values; args->capacity = capacity;
    }
    args->values[args->count++] = value;
    args->values[args->count] = NULL;
}
void shroot_option(struct shroot_arguments *args, const char *name, const char *value) {
    if (value) { shroot_argument(args, name); shroot_argument(args, value); }
}
static int owned_io(int fd, int output) {
    int opened = -1;
    if (fd < -1) return -EINVAL;
    if (fd < 0) {
        opened = open("/dev/null", (output ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
        if (opened < 0) return -errno;
        fd = opened;
    }
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 4), r = copy < 0 ? -errno : copy;
    if (opened >= 0) close(opened);
    return r;
}
int shroot_client_start(shroot_context *context, struct shroot_arguments *args,
        const struct shroot_io *io, shroot_job **out) {
    int r = !context || !out ? -EINVAL : args->error;
    if (out) *out = NULL;
    if (!r && (!args->count || !args->values[0])) r = -EINVAL;
    struct sigaction child_action;
    if (!r && sigaction(SIGCHLD, NULL, &child_action)) r = -errno;
    if (!r && (child_action.sa_handler == SIG_IGN || (child_action.sa_flags & SA_NOCLDWAIT))) r = -ENOTSUP;
    shroot_job *job = r ? NULL : calloc(1, sizeof(*job));
    if (!r && !job) r = -ENOMEM;
    struct shroot_arguments command = {0};
    if (!r) {
        atomic_init(&job->finished, 0);
        job->process = job->channel = -1;
        const char *operation=args->values[0];
        if (!strcmp(operation,"library") && args->count>=3) operation=args->values[2];
        job->launch = !strcmp(operation, "run") || !strcmp(operation, "exec") || !strcmp(operation, "login");
        shroot_argument(&command, context->worker);
        shroot_argument(&command, SHROOT_CLIENT_OPTION);
        for (size_t i = 0; i < args->count; ++i) shroot_argument(&command, args->values[i]);
        r = command.error;
    }
    int channel[2] = {-1, -1}, descriptors[4] = {-1, -1, -1, -1};
    /* Capture stdio before allocating sockets: a closed standard descriptor
     * must not accidentally become the newly allocated control channel. */
    for (int i = 0; !r && i < 3; ++i) {
        int fd = io ? i == 0 ? io->input : i == 1 ? io->output : io->error : i;
        descriptors[i] = owned_io(fd, i != 0);
        if (descriptors[i] < 0) r = descriptors[i];
    }
    if (!r && socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel)) r = -errno;
    if (!r && (descriptors[3] = owned_io(channel[1], 1)) < 0) r = descriptors[3];
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int actions_open = 0, attributes_open = 0;
    if (!r) { r = -posix_spawn_file_actions_init(&actions); actions_open = !r; }
    if (!r) { r = -posix_spawnattr_init(&attributes); attributes_open = !r; }
    for (int i = 0; !r && i < 4; ++i) r = -posix_spawn_file_actions_adddup2(&actions, descriptors[i], i);
    sigset_t mask, defaults;
    sigemptyset(&mask); sigemptyset(&defaults);
    const int signals[] = {SIGCHLD, SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGPIPE};
    for (size_t i = 0; i < sizeof(signals) / sizeof(*signals); ++i) sigaddset(&defaults, signals[i]);
    if (!r) r = -posix_spawnattr_setsigmask(&attributes, &mask);
    if (!r) r = -posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!r) r = -posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    if (!r) r = -posix_spawn(&job->pid, context->worker, &actions, &attributes,
        (char *const *)command.values, io && io->environment ? io->environment : environ);
    if (actions_open) posix_spawn_file_actions_destroy(&actions);
    if (attributes_open) posix_spawnattr_destroy(&attributes);
    for (int i = 0; i < 4; ++i) if (descriptors[i] >= 0) close(descriptors[i]);
    if (channel[1] >= 0) close(channel[1]);
    if (!r) {
        job->process = syscall(SYS_pidfd_open, job->pid, 0);
        if (job->process < 0) r = -errno;
        struct shroot_client_message admission = {SHROOT_CLIENT_MAGIC, SHROOT_CLIENT_ADMIT, 0, 0};
        if (!r) {
            ssize_t sent;
            do { sent = send(channel[0], &admission, sizeof(admission), MSG_NOSIGNAL | MSG_DONTWAIT); } while (sent < 0 && errno == EINTR);
            if (sent != sizeof(admission)) r = sent < 0 ? -errno : -EIO;
        }
        if (r) {
            /* This library exclusively owns reaping this child. A live child
             * cannot recycle its PID before the following waitpid. Admission
             * keeps the worker from changing storage before we own its pidfd. */
            if (job->process >= 0) { syscall(SYS_pidfd_send_signal, job->process, SIGKILL, NULL, 0); close(job->process); }
            else kill(job->pid, SIGKILL);
            while (waitpid(job->pid, NULL, 0) < 0 && errno == EINTR) {}
        }
    }
    free(command.values); free(args->values);
    if (r) { if (channel[0] >= 0) close(channel[0]); free(job); return r; }
    job->channel = channel[0]; *out = job; return 0;
}
int shroot_job_fd(const shroot_job *job) { return job ? job->process : -EINVAL; }
pid_t shroot_job_pid(const shroot_job *job) { return job ? job->pid : -1; }
int shroot_job_signal(shroot_job *job, int signal) {
    if (!job) return -EINVAL;
    if (signal < 0 || signal >= NSIG) return -EINVAL;
    if (atomic_load_explicit(&job->finished, memory_order_acquire)) return 0;
    return syscall(SYS_pidfd_send_signal, job->process, signal, NULL, 0) && errno != ESRCH ? -errno : 0;
}
int shroot_job_cancel(shroot_job *job) { return shroot_job_signal(job, SIGTERM); }
int shroot_job_wait(shroot_job *job, int nonblocking, struct shroot_result *out) {
    if (!job || !out) return -EINVAL;
    if (!atomic_load_explicit(&job->finished, memory_order_acquire)) {
        int status;
        pid_t pid;
        /* EVENT_WAIT: this owned child exits; nonblocking callers use its pidfd. */
        do { pid = waitpid(job->pid, &status, nonblocking ? WNOHANG : 0); } while (pid < 0 && errno == EINTR);
        if (!pid) return -EAGAIN;
        if (pid < 0) return -errno;
        int began = 0, done = 0, error = 0;
        for (;;) {
            struct shroot_client_message message;
            ssize_t n = recv(job->channel, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0 && errno == EINTR) continue;
            if (!n) break;
            if (n < 0) {
                if (errno != ECONNRESET || !WIFSIGNALED(status)) error = -EPROTO;
                break;
            }
            if (n != sizeof(message) || message.magic != SHROOT_CLIENT_MAGIC || message.reserved
                    || message.error > 0 || message.error < -4095 || done) { error = -EPROTO; break; }
            if (message.phase == SHROOT_CLIENT_BEGIN && !began && !message.error) began = 1;
            else if (message.phase == SHROOT_CLIENT_DONE && began) { done = 1; error = message.error; }
            else { error = -EPROTO; break; }
        }
        job->result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        job->result.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        if (!error && !job->result.signal && (!began || (!done && !job->launch))) error = -EPROTO;
        job->result.error = error;
        close(job->channel); job->channel = -1;
        atomic_store_explicit(&job->finished, 1, memory_order_release);
    }
    *out = job->result; return 0;
}
int shroot_job_close(shroot_job *job) {
    if (!job) return 0;
    if (!atomic_load_explicit(&job->finished, memory_order_acquire)) return -EBUSY;
    close(job->process); free(job); return 0;
}
