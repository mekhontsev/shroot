#define _GNU_SOURCE
#include "cli_library.h"
#include "attachment_option.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <unistd.h>

int cli_launch(shroot_store *store, shroot_library *library, const char *name,
        enum shroot_launch_kind kind, int argc, char **argv, shroot_job **out) {
    struct shroot_launch_options options = {.kind=kind};
    const char **env = calloc((size_t)argc + 1, sizeof(*env));
    const char **dns = calloc((size_t)argc + 1, sizeof(*dns));
    const char **ports = calloc((size_t)argc + 1, sizeof(*ports));
    const char **subnets = calloc((size_t)argc + 1, sizeof(*subnets));
    const char **gateways = calloc((size_t)argc + 1, sizeof(*gateways));
    struct shroot_bind *binds = calloc((size_t)argc + 1, sizeof(*binds));
    struct shroot_socket_route *routes = calloc((size_t)argc + 1, sizeof(*routes));
    int *owners = calloc((size_t)argc + 1, sizeof(*owners));
    int r = env && dns && ports && subnets && gateways && binds && routes && owners ? 0 : -ENOMEM;
    size_t env_count = 0, dns_count = 0, port_count = 0;
    size_t subnet_count = 0, gateway_count = 0;
    int at = 0;
    while (!r && at < argc && strcmp(argv[at], "--")) {
        const char *name = argv[at++];
        if (!strcmp(name, "--statistics")) { options.flags |= SHROOT_STATISTICS; continue; }
        if (!strcmp(name, "--diagnostics")) { options.flags |= SHROOT_DIAGNOSTICS; continue; }
        if (!strcmp(name, "--diagnostics=signals")) { options.flags |= SHROOT_SIGNAL_DIAGNOSTICS; continue; }
        int bind_kind = md_attachment_kind(name);
        if (bind_kind >= 0) {
            if (at + 1 >= argc) { r = -EINVAL; break; }
            binds[options.bind_count++] = (struct shroot_bind){bind_kind, argv[at], argv[at+1]};
            at += 2; continue;
        }
        const char *route_names[] = {"--socket-path", "--socket-abstract", "--socket-resource-path", "--socket-resource-abstract"};
        int multiple = 0;
        for (int i = 0; i < 4; ++i) {
            if (strcmp(name, route_names[i])) continue;
            multiple = 1;
            if (at + 1 >= argc) { r = -EINVAL; break; }
            routes[options.route_count++] = (struct shroot_socket_route){i, argv[at], argv[at+1]};
            at += 2; break;
        }
        if (multiple) continue;
        if (at >= argc) { r = -EINVAL; break; }
        const char *value = argv[at++];
        if (!strcmp(name, "--env")) env[env_count++] = value;
        else if (!strcmp(name, "--owner-fd")) {
            char *end; errno = 0;
            long fd = strtol(value, &end, 10);
            if (errno || !*value || *end || fd < 3 || fd > INT_MAX) r = -EINVAL;
            else owners[options.owner_fd_count++] = (int)fd;
        }
        else if (!strcmp(name, "--dns")) dns[dns_count++] = value;
        else if (!strcmp(name, "-p") || !strcmp(name, "--publish")) ports[port_count++] = value;
        else if (!strcmp(name, "--subnet")) subnets[subnet_count++] = value;
        else if (!strcmp(name, "--gateway")) gateways[gateway_count++] = value;
        else {
            struct { const char *name; const char **value; } scalars[] = {
                {"--user", &options.user}, {"--cwd", &options.cwd}, {"--entrypoint", &options.entrypoint},
                {"--hostname", &options.hostname}, {"--gamepad-endpoint", &options.gamepad_endpoint},
                {"--path-prefix", &options.path_prefix},
                {"--network", &options.network}, {"--ip", &options.ip}, {"--ip6", &options.ip6}
            };
            r = -EINVAL;
            for (size_t i = 0; i < sizeof(scalars)/sizeof(*scalars); ++i) {
                if (strcmp(name, scalars[i].name) || *scalars[i].value) continue;
                *scalars[i].value = value; r = 0; break;
            }
        }
    }
    if (at < argc && !strcmp(argv[at], "--")) ++at;
    options.arguments = (const char *const *)(argv + at);
    options.environment = env; options.dns = dns; options.ports = ports;
    options.subnets = subnets; options.gateways = gateways;
    options.binds = binds; options.routes = routes;
    options.owner_fds = owners;
    if (!r) r = library ? shroot_environment_launch(library,name,&options,NULL,out) : shroot_launch(store, &options, NULL, out);
    free(env); free(dns); free(ports); free(subnets); free(gateways); free(binds); free(routes); free(owners); return r;
}
static int submit(shroot_context *context, int argc, char **argv, shroot_job **out) {
    if (!argc) return -EINVAL;
    const char *name = argv[0];
    if (argc == 1 && !strcmp(name, "format")) return shroot_storage_format(context, NULL, out);
    if (argc == 1 && !strcmp(name, "import-version")) return shroot_import_version(context, NULL, out);
    if (argc == 2 && !strcmp(name, "recover-staging")) return shroot_recover_staging(context, argv[1], NULL, out);
    if (argc == 2 && !strcmp(name, "remove-layer")) return shroot_remove_layer(context, argv[1], NULL, out);
    if (argc == 3 && !strcmp(name, "relocate-library")) return shroot_relocate_library(context, argv[1], argv[2], NULL, out);
    if (argc == 3 && (!strcmp(name, "rootfs") || !strcmp(name, "restore")))
        return shroot_import_archive(context, !strcmp(name, "rootfs") ? SHROOT_ROOTFS : SHROOT_BACKUP, argv[1], argv[2], NULL, out);
    if (argc >= 4 && !strcmp(name, "import")) {
        struct shroot_oci_import options = {.layout=argv[1], .destination=argv[2]};
        if (!strcmp(argv[3], "--preserve-ownership")) options.preserve_ownership = 1;
        else if (strcmp(argv[3], "--map-current-user")) return -EINVAL;
        for (int i = 4; i < argc; i += 2) {
            if (i+1 >= argc) return -EINVAL;
            if (!strcmp(argv[i], "--reference") && !options.reference) options.reference = argv[i+1];
            else if (!strcmp(argv[i], "--layers") && !options.layers) options.layers = argv[i+1];
            else if (!strcmp(argv[i], "--blobs") && !options.blobs) options.blobs = argv[i+1];
            else return -EINVAL;
        }
        return shroot_import_oci(context, &options, NULL, out);
    }
    if (argc < 2) return -EINVAL;
    shroot_store *store = NULL;
    int r = shroot_store_open(context, argv[1], &store);
    if (r) return r;
    struct { const char *name; int (*function)(shroot_store *, const struct shroot_io *, shroot_job **); } unary[] = {
        {"inspect", shroot_inspect}, {"prepare", shroot_prepare}, {"maintain", shroot_maintain},
        {"remove", shroot_remove}, {"sources", shroot_sources}, {"relative-sources", shroot_relative_sources},
        {"launches", shroot_launches}, {"applications", shroot_applications}
    };
    r = -EINVAL;
    if (argc == 2) for (size_t i = 0; i < sizeof(unary)/sizeof(*unary); ++i)
        if (!strcmp(name, unary[i].name)) { r = unary[i].function(store, NULL, out); break; }
    if (argc == 3 && !strcmp(name, "create")) r = shroot_clone(store, argv[2], NULL, out);
    else if (argc == 3 && !strcmp(name, "backup")) r = shroot_backup(store, argv[2], NULL, out);
    else if (argc == 3 && !strcmp(name, "stop")) r = shroot_stop(store, argv[2], NULL, out);
    else if (argc == 3 && !strcmp(name, "icon")) r = shroot_icon(store, argv[2], NULL, out);
    else if (argc == 4 && !strcmp(name, "export-tree")) r = shroot_export_tree(store, argv[2], argv[3], NULL, out);
    else if ((argc == 3 || (argc == 4 && !strcmp(argv[3], "--replace"))) && !strcmp(name, "resolver"))
        r = shroot_resolver(store, argv[2], argc == 4, NULL, out);
    else if (!strcmp(name, "run") || !strcmp(name, "exec") || !strcmp(name, "login"))
        r = cli_launch(store, NULL, NULL, !strcmp(name, "run") ? SHROOT_RUN : !strcmp(name, "exec") ? SHROOT_EXEC : SHROOT_LOGIN, argc-2, argv+2, out);
    shroot_store_close(store); return r;
}
static int runtime_directory(char path[PATH_MAX]) {
    ssize_t n = readlink("/proc/self/exe", path, PATH_MAX-1);
    if (n < 0) return -errno;
    if (!n || n == PATH_MAX-1) return -ENAMETOOLONG;
    path[n] = 0;
    char *last = strrchr(path, '/');
    if (!last) return -EINVAL;
    *last = 0;
    char worker[PATH_MAX];
    if (snprintf(worker, sizeof(worker), "%s/libshroot_guest_image.so", path) >= (int)sizeof(worker)) return -ENAMETOOLONG;
    if (!access(worker, X_OK)) return 0;
    if (strlen(path) + sizeof("/../libexec/shroot") > PATH_MAX) return -ENAMETOOLONG;
    strcat(path, "/../libexec/shroot"); return 0;
}
static void usage(void) {
    puts("Usage: shroot [--library DIR] [--runtime DIR] [--parent-pid PID] COMMAND [ARGS]\n"
        "  --print-library | init | list | prune | resolve NAME | remove NAME\n"
        "  install SOURCE [--rootfs|--oci] --name NAME [--resolver CONTENTS]\n"
        "      [--ca-file FILE] [--ca-directory DIRECTORY] (registry only)\n"
        "  backup NAME ARCHIVE | restore ARCHIVE --name NAME\n"
        "  exec|run|login NAME [OPTIONS] [-- COMMAND...]\n"
        "  A bare name selects an environment; use ./STORE or /path for a store.\n"
        "  rootfs ARCHIVE NEW_IMAGE | import OCI_LAYOUT NEW_IMAGE --preserve-ownership\n"
        "  create IMAGE NEW_INSTANCE | restore ARCHIVE NEW_INSTANCE\n"
        "  inspect STORE | prepare STORE | maintain STORE | remove STORE\n"
        "  backup STORE NEW_ARCHIVE | sources STORE | launches STORE | stop STORE ID\n"
        "  run STORE [OPTIONS] [-- COMMAND...] | exec STORE [OPTIONS] -- COMMAND...\n"
        "  login STORE [OPTIONS] [-- SHELL...]\n"
        "  Options: --user USER --cwd PATH --env KEY=VALUE --network MODE --dns IP\n"
        "           --bind HOST GUEST --bind-ro HOST GUEST --bind-ro-create HOST GUEST --statistics\n"
        "           --bind-fuse SOCKET GUEST --bind-fuse-ro SOCKET GUEST\n"
        "  --version | format | import-version");
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts(shroot_version()); return 0; }
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "--help"))) { usage(); return argc == 1 ? 2 : 0; }
    char runtime[PATH_MAX]; const char *directory = NULL, *parent = NULL, *library = NULL;
    int at = 1, r = 0;
    while (!r && at < argc) {
        const char **option = !strcmp(argv[at], "--runtime") ? &directory
            : !strcmp(argv[at], "--parent-pid") ? &parent
            : !strcmp(argv[at], "--library") ? &library : NULL;
        if (!option) break;
        if (*option || at + 1 >= argc || !*argv[at+1]) { r = -EINVAL; break; }
        *option = argv[at+1]; at += 2;
    }
    if (!r && parent) {
        char *end;
        errno = 0;
        long pid = strtol(parent, &end, 10);
        if (errno || !*parent || *end || pid <= 1 || pid > INT_MAX) r = -EINVAL;
        else if (prctl(PR_SET_PDEATHSIG, SIGTERM)) r = -errno;
        else if (getppid() != pid) r = -ECHILD;
    }
    if (!r && argc-at == 1 && !strcmp(argv[at], "--print-library")) {
        char path[PATH_MAX];
        if (library || !(r = cli_default_library(path))) { puts(library ? library : path); return 0; }
    }
    if (!r && !directory) { r = runtime_directory(runtime); directory = runtime; }
    shroot_context *context = NULL;
    if (!r) r = shroot_context_open(directory, &context);
    sigset_t mask;
    sigemptyset(&mask);
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    for (size_t i = 0; i < sizeof(signals)/sizeof(*signals); ++i) sigaddset(&mask, signals[i]);
    if (!r && sigprocmask(SIG_BLOCK, &mask, NULL)) r = -errno;
    int signal_fd = r ? -1 : signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (!r && signal_fd < 0) r = -errno;
    shroot_job *job = NULL;
    if (!r) r = library || cli_named_command(argc-at, argv+at)
        ? cli_library_submit(context, library, argc-at, argv+at, &job)
        : submit(context, argc-at, argv+at, &job);
    struct shroot_result result = {0};
    while (!r && job) {
        r = shroot_job_wait(job, 1, &result);
        if (r != -EAGAIN) break;
        struct pollfd fds[] = {{shroot_job_fd(job), POLLIN, 0}, {signal_fd, POLLIN, 0}};
        /* EVENT_WAIT: operation exit or CLI cancellation, without polling. */
        do { r = poll(fds, 2, -1); } while (r < 0 && errno == EINTR);
        if (r < 0) { r = -errno; break; }
        r = 0;
        struct signalfd_siginfo signal;
        while (read(signal_fd, &signal, sizeof(signal)) == sizeof(signal))
            if (!r) r = shroot_job_signal(job, signal.ssi_signo);
    }
    if (job) {
        if (r) { shroot_job_cancel(job); shroot_job_wait(job, 0, &result); }
        shroot_job_close(job);
    }
    if (signal_fd >= 0) close(signal_fd);
    shroot_context_close(context);
    if (r) { fprintf(stderr, "shroot: %s\n", strerror(-r)); return 125; }
    if (result.error) return 1;
    return result.signal ? 128 + result.signal : result.exit_code;
}
