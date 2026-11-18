#define _GNU_SOURCE
#include "cli_library.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int cli_default_library(char path[PATH_MAX]) {
    const char *base = SHROOT_DEFAULT_LIBRARY, *suffix = "";
    if (!*base) {
        base = getenv("XDG_DATA_HOME");
        suffix = "/shroot";
        if (!base || *base != '/') {
            base = getenv("HOME");
            suffix = "/.local/share/shroot";
            if (!base || *base != '/') {
                fprintf(stderr, "shroot: set an absolute HOME or XDG_DATA_HOME, or select --library DIR\n");
                return -EINVAL;
            }
        }
    }
    size_t n = strlen(base);
    while (n > 1 && base[n-1] == '/') --n;
    if (n == 1 && *suffix == '/') ++suffix;
    if (n + strlen(suffix) >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(path, base, n);
    strcpy(path+n, suffix);
    return 0;
}

int cli_named_command(int argc, char **argv) {
    if (argc < 1) return 0;
    const char *op = argv[0];
    if (!strcmp(op, "init") || !strcmp(op, "list") || !strcmp(op, "prune") ||
        !strcmp(op, "resolve") || !strcmp(op, "install")) return 1;
    if (!strcmp(op, "restore")) return argc >= 3 && !strcmp(argv[2], "--name");
    if (!strcmp(op, "run") || !strcmp(op, "exec") || !strcmp(op, "login") ||
        !strcmp(op, "backup") || !strcmp(op, "remove") || !strcmp(op, "resolver"))
        return argc >= 2 && !strchr(argv[1], '/') && strcmp(argv[1], ".") && strcmp(argv[1], "..");
    return 0;
}

/* Only the CLI's implicit location needs first-use XDG/package parents.
 * Never create the catalog itself here: its image owner admits and locks it. */
static int default_parents(char *path, int create) {
    for (char *p = path + 1; (p = strchr(p, '/')); ++p) {
        *p = 0;
        struct stat st;
        int r = 0;
        if (stat(path, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) r = -ENOTDIR;
        } else if (errno != ENOENT) r = -errno;
        else if (create) {
            if (mkdir(path, 0700) && errno != EEXIST) r = -errno;
            else if (stat(path, &st)) r = -errno;
            else if (!S_ISDIR(st.st_mode)) r = -ENOTDIR;
        } else if (!lstat(path, &st)) r = -ENOENT; /* dangling parent */
        else if (errno != ENOENT) r = -errno;
        *p = '/';
        if (r) return r;
    }
    return 0;
}

static int install_options(int argc, char **argv, struct shroot_install_options *options) {
    if (argc < 4) return -EINVAL;
    options->source = argv[1];
    options->kind = SHROOT_SOURCE_REGISTRY;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--oci") || !strcmp(argv[i], "--rootfs")) {
            if (options->kind != SHROOT_SOURCE_REGISTRY) return -EINVAL;
            options->kind = !strcmp(argv[i], "--oci") ? SHROOT_SOURCE_OCI : SHROOT_SOURCE_ROOTFS;
            continue;
        }
        const char **field = !strcmp(argv[i], "--name") ? &options->name :
            !strcmp(argv[i], "--resolver") ? &options->resolver :
            !strcmp(argv[i], "--ca-file") ? &options->ca_file :
            !strcmp(argv[i], "--ca-directory") ? &options->ca_directory : NULL;
        if (!field || *field || ++i == argc || !*argv[i]) return -EINVAL;
        *field = argv[i];
    }
    return options->name && (options->kind == SHROOT_SOURCE_REGISTRY ||
           (!options->ca_file && !options->ca_directory)) ? 0 : -EINVAL;
}

int cli_library_submit(shroot_context *context, const char *selected, int argc,
                       char **argv, shroot_job **job) {
    if (!cli_named_command(argc, argv)) return -EINVAL;
    const char *op = argv[0];
    int install = !strcmp(op, "install"), init = argc == 1 && !strcmp(op, "init");
    int restore = argc == 4 && !strcmp(op, "restore"), list = argc == 1 && !strcmp(op, "list");
    struct shroot_install_options options = {0};
    int r = install ? install_options(argc, argv, &options) : 0;
    if (r) return r;
    char path[PATH_MAX];
    if (!selected) {
        if ((r = cli_default_library(path))) return r;
        struct stat st;
        if (list && lstat(path, &st) && errno == ENOENT) {
            if (!(r = default_parents(path, 0))) { puts("[]"); return 0; }
        } else if (init || install || restore) r = default_parents(path, 1);
        if (r) { fprintf(stderr, "shroot: library %s: %s\n", path, strerror(-r)); return r; }
        selected = path;
    }
    shroot_library *library = NULL;
    if ((r = shroot_library_open(context, selected, &library))) return r;
    if (init) r = shroot_library_initialize(library, NULL, job);
    else if (list) r = shroot_library_list(library, NULL, job);
    else if (install) r = shroot_environment_install(library, &options, NULL, job);
    else if (restore) r = shroot_environment_restore(library, argv[1], argv[3], NULL, job);
    else if (argc == 1 && !strcmp(op, "prune")) r = shroot_library_prune(library, NULL, job);
    else if (argc == 2 && !strcmp(op, "resolve")) r = shroot_environment_resolve(library, argv[1], NULL, job);
    else if (argc == 2 && !strcmp(op, "remove")) r = shroot_environment_remove(library, argv[1], NULL, job);
    else if (argc == 3 && !strcmp(op, "backup")) r = shroot_environment_backup(library, argv[1], argv[2], NULL, job);
    else if ((argc == 3 || (argc == 4 && !strcmp(argv[3], "--replace"))) && !strcmp(op, "resolver"))
        r = shroot_environment_resolver(library, argv[1], argv[2], argc == 4, NULL, job);
    else if (argc >= 2 && (!strcmp(op, "run") || !strcmp(op, "exec") || !strcmp(op, "login")))
        r = cli_launch(NULL, library, argv[1], !strcmp(op, "run") ? SHROOT_RUN :
                       !strcmp(op, "exec") ? SHROOT_EXEC : SHROOT_LOGIN, argc-2, argv+2, job);
    else r = -EINVAL;
    shroot_library_close(library);
    return r;
}
