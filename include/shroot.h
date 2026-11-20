#ifndef SHROOT_H
#define SHROOT_H

#include <stddef.h>
#include <sys/types.h>

#if defined(__GNUC__)
#pragma GCC visibility push(default)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct shroot_context shroot_context;
typedef struct shroot_store shroot_store;
typedef struct shroot_library shroot_library;
typedef struct shroot_job shroot_job;

/* All functions return zero or a negative errno unless documented otherwise.
 * No function changes the caller's identity, cwd, umask, signals or environment.
 * Contexts outlive their stores; jobs are independent after submission. */
const char *shroot_version(void);
int shroot_context_open(const char *runtime_directory, shroot_context **out);
void shroot_context_close(shroot_context *);
int shroot_store_open(shroot_context *, const char *path, shroot_store **out);
void shroot_store_close(shroot_store *);
/* Captures the absolute catalog path; performs no IO or mutation of the catalog.
 * Contexts outlive their libraries. Initialize/install creates a missing root
 * whose parent exists; reads/removal never implicitly create it. */
int shroot_library_open(shroot_context *, const char *path, shroot_library **out);
void shroot_library_close(shroot_library *);

/* NULL inherits standard IO and the host environment. Other descriptors are
 * closed in the worker. Supplied descriptors are borrowed until start returns;
 * use -1 for /dev/null. environment is an explicit, NULL-terminated envp, or NULL
 * to inherit. Guest environment overrides belong to shroot_launch_options. */
struct shroot_io {
    int input, output, error;
    char *const *environment;
};

/* Completion separates backend errors from a guest's ordinary exit status.
 * error is zero or negative errno; signal is zero for normal exit. */
struct shroot_result { int error, exit_code, signal; };
/* Borrowed pollable descriptor. Readiness means completion, not guest startup. */
int shroot_job_fd(const shroot_job *);
pid_t shroot_job_pid(const shroot_job *);
/* nonblocking returns -EAGAIN while active. Repeated waits return the same result.
 * The application must not reap this child through another waitpid owner.
 * Submission rejects SIGCHLD=SIG_IGN/SA_NOCLDWAIT instead of changing them. */
int shroot_job_wait(shroot_job *, int nonblocking, struct shroot_result *);
int shroot_job_cancel(shroot_job *);
int shroot_job_signal(shroot_job *, int signal);
/* Returns -EBUSY until waited. Never silently detaches or kills a running tree. */
int shroot_job_close(shroot_job *);

enum shroot_archive_kind { SHROOT_ROOTFS, SHROOT_BACKUP };
struct shroot_oci_import {
    const char *layout, *destination, *reference, *layers, *blobs;
    int preserve_ownership;
};
int shroot_import_oci(shroot_context *, const struct shroot_oci_import *, const struct shroot_io *, shroot_job **);
int shroot_import_archive(shroot_context *, enum shroot_archive_kind, const char *archive,
    const char *destination, const struct shroot_io *, shroot_job **);
int shroot_clone(shroot_store *, const char *destination, const struct shroot_io *, shroot_job **);
int shroot_backup(shroot_store *, const char *destination, const struct shroot_io *, shroot_job **);
int shroot_inspect(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_prepare(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_maintain(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_remove(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_sources(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_relative_sources(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_launches(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_stop(shroot_store *, const char *launch_id, const struct shroot_io *, shroot_job **);
int shroot_applications(shroot_store *, const struct shroot_io *, shroot_job **);
int shroot_icon(shroot_store *, const char *name, const struct shroot_io *, shroot_job **);
int shroot_export_tree(shroot_store *, const char *guest_path, const char *destination,
    const struct shroot_io *, shroot_job **);
int shroot_resolver(shroot_store *, const char *servers, int replace, const struct shroot_io *, shroot_job **);
int shroot_recover_staging(shroot_context *, const char *directory, const struct shroot_io *, shroot_job **);
int shroot_relocate_library(shroot_context *, const char *source, const char *destination,
    const struct shroot_io *, shroot_job **);
/* Caller must first verify persistent dependents, as with store removal. */
int shroot_remove_layer(shroot_context *, const char *path, const struct shroot_io *, shroot_job **);
int shroot_storage_format(shroot_context *, const struct shroot_io *, shroot_job **);
int shroot_import_version(shroot_context *, const struct shroot_io *, shroot_job **);

enum shroot_source_kind { SHROOT_SOURCE_ROOTFS, SHROOT_SOURCE_OCI, SHROOT_SOURCE_REGISTRY };
struct shroot_install_options {
    enum shroot_source_kind kind;
    const char *source, *name, *resolver;
    /* Optional HTTPS trust for registry pulls; NULL selects host certificates. */
    const char *ca_file, *ca_directory;
};
int shroot_library_initialize(shroot_library *, const struct shroot_io *, shroot_job **);
int shroot_library_list(shroot_library *, const struct shroot_io *, shroot_job **);
int shroot_library_prune(shroot_library *, const struct shroot_io *, shroot_job **);
int shroot_environment_resolve(shroot_library *, const char *name, const struct shroot_io *, shroot_job **);
int shroot_environment_remove(shroot_library *, const char *name, const struct shroot_io *, shroot_job **);
int shroot_environment_install(shroot_library *, const struct shroot_install_options *, const struct shroot_io *, shroot_job **);
int shroot_environment_restore(shroot_library *, const char *archive, const char *name, const struct shroot_io *, shroot_job **);
int shroot_environment_backup(shroot_library *, const char *name, const char *archive, const struct shroot_io *, shroot_job **);
int shroot_environment_resolver(shroot_library *, const char *name, const char *servers, int replace,
    const struct shroot_io *, shroot_job **);

enum shroot_launch_kind { SHROOT_RUN, SHROOT_EXEC, SHROOT_LOGIN };
enum shroot_bind_kind { SHROOT_BIND, SHROOT_BIND_READONLY, SHROOT_BIND_CREATE, SHROOT_BIND_STORE_READONLY,
    SHROOT_BIND_READONLY_CREATE, SHROOT_BIND_FUSE, SHROOT_BIND_FUSE_READONLY };
struct shroot_bind { enum shroot_bind_kind kind; const char *source, *target; };
enum shroot_socket_kind { SHROOT_SOCKET_PATH, SHROOT_SOCKET_ABSTRACT,
    SHROOT_SOCKET_RESOURCE_PATH, SHROOT_SOCKET_RESOURCE_ABSTRACT };
struct shroot_socket_route { enum shroot_socket_kind kind; const char *source, *target; };
enum shroot_launch_flags {
    SHROOT_STATISTICS = 1,
    SHROOT_DIAGNOSTICS = 2,
    SHROOT_SIGNAL_DIAGNOSTICS = 4
};
struct shroot_launch_options {
    enum shroot_launch_kind kind;
    unsigned flags;
    const char *user, *cwd, *entrypoint, *hostname, *gamepad_endpoint;
    const char *network, *ip, *ip6;
    const char *const *arguments;
    const char *const *environment;
    const char *const *dns;
    const char *const *ports;
    /* One subnet/gateway per address family, validated by the network owner. */
    const char *const *subnets;
    const char *const *gateways;
    const struct shroot_bind *binds;
    size_t bind_count;
    const struct shroot_socket_route *routes;
    size_t route_count;
    /* Borrowed until submission returns. Private copies remain in the supervisor
     * until its tree ends; never installed in the guest or read by Shroot.
     * The caller retains its descriptors and is responsible for closing them. */
    const int *owner_fds;
    size_t owner_fd_count;
    /* Added before the final guest PATH, preserving image and explicit values. */
    const char *path_prefix;
};
/* EXEC starts a new supervised tree in this store, not an exec in a live tree.
 * The runtime, including PTY and process-tree cleanup, remains out of process. */
int shroot_launch(shroot_store *, const struct shroot_launch_options *, const struct shroot_io *, shroot_job **);
int shroot_environment_launch(shroot_library *, const char *name, const struct shroot_launch_options *,
    const struct shroot_io *, shroot_job **);

#ifdef __cplusplus
}
#endif
#if defined(__GNUC__)
#pragma GCC visibility pop
#endif
#endif
