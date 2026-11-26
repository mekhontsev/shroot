#define _GNU_SOURCE
#include "image_io.h"
#include "image_import.h"
#include "image_library.h"
#include "image_launch.h"
#include "image_publish.h"
#include "image_backup.h"
#include "image_maintenance.h"
#include "image_prepare.h"
#include "image_export.h"
#include "launch_registry.h"
int md_image_launches(const char *store);
int md_image_applications(const char *store, const char *icon);
#include "image_presentation.h"
#include "inode_internal.h"
#include "launch_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/socket.h>
#include "client_protocol.h"
#include "process_owner.h"

static int execute(int argc, char **argv) {
    const char *owner = getenv("SHROOT_IMAGE_OWNER_PID");
    if (owner) {
        char *end;
        long pid = strtol(owner, &end, 10);
        if (!*owner || *end || pid <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != pid) return -ECHILD;
        unsetenv("SHROOT_IMAGE_OWNER_PID");
    }
    if (!md_launch_identity(getuid(),geteuid(),getgid(),getegid())) return -EACCES;
    umask(0);
    const char *reference = NULL, *pool = NULL, *blobs = NULL;
    int r = -EINVAL;
    if (argc >= 3 && !strcmp(argv[1], "library")) return md_library_command(argc-2,argv+2);
    if (argc >= 5 && !strcmp(argv[1], "import")
            && (!strcmp(argv[4], "--map-current-user") || !strcmp(argv[4], "--preserve-ownership"))) {
        for (int i=5; i<argc; i+=2) {
            if (i+1 == argc) return -EINVAL;
            if (!strcmp(argv[i], "--reference") && !reference) reference = argv[i+1];
            else if (!strcmp(argv[i], "--layers") && !pool) pool = argv[i+1];
            else if (!strcmp(argv[i], "--blobs") && !blobs) blobs = argv[i+1];
            else return -EINVAL;
        }
        r = md_image_import(argv[2], argv[3], reference, !strcmp(argv[4], "--preserve-ownership"), pool, blobs);
    } else if (argc == 2 && !strcmp(argv[1], "format")) { printf("%d\n", md_inode_store_format()); r = 0; }
    /* Import semantics, not the SQLite layout or runtime build. Keep this key
     * stable across metadata upgrades so installed sources retain identity. */
    else if (argc == 2 && !strcmp(argv[1], "import-version")) { printf("%d\n",MD_IMAGE_IMPORT_VERSION); r = 0; }
    else if (argc == 3 && !strcmp(argv[1], "prepare")) {
        struct md_inode_store *store=NULL;
        r=md_inode_store_open(argv[2],0,&store);
        md_inode_store_close(store);
    }
    else if (argc == 3 && !strcmp(argv[1], "maintain")) {
        struct md_inode_store *store=NULL;
        r=md_inode_store_open_exclusive(argv[2],&store);
        md_inode_store_close(store);
    }
    else if (argc == 4 && !strcmp(argv[1], "create")) r = md_image_create(argv[2], argv[3]);
    else if (argc == 4 && !strcmp(argv[1], "backup")) r = md_image_backup(argv[2], argv[3]);
    else if (argc == 4 && !strcmp(argv[1], "restore")) r = md_image_archive_import(argv[2], argv[3], 1);
    else if (argc == 4 && !strcmp(argv[1], "rootfs")) r = md_image_archive_import(argv[2], argv[3], 0);
    else if (argc == 3 && !strcmp(argv[1], "remove")) r = md_image_remove(argv[2], 0);
    else if (argc == 3 && !strcmp(argv[1], "remove-layer")) r = md_image_remove(argv[2], 1);
    else if (argc == 3 && !strcmp(argv[1], "sources")) r = md_image_sources(argv[2]);
    else if (argc == 3 && !strcmp(argv[1], "relative-sources")) {
        char directory[PATH_MAX];
        r=realpath(argv[2],directory) ? md_image_rebase_sources(directory,directory) : -errno;
    }
    else if (argc == 4 && !strcmp(argv[1], "relocate-library")) r=md_image_relocate_library(argv[2],argv[3]);
    else if (argc == 3 && !strcmp(argv[1], "inspect")) r = md_image_inspect(argv[2]);
    else if (argc == 3 && !strcmp(argv[1], "recover-staging")) r = md_image_publish_recover(argv[2]);
    else if (argc == 3 && !strcmp(argv[1], "launches")) r = md_image_launches(argv[2]);
    else if (argc == 4 && !strcmp(argv[1], "stop")) r = md_launch_stop(argv[2], argv[3]);
    else if (argc == 3 && !strcmp(argv[1], "applications")) r = md_image_applications(argv[2], NULL);
    else if (argc == 3 && !strcmp(argv[1], "os-info")) r = md_image_os_info(argv[2]);
    else if (argc == 4 && !strcmp(argv[1], "icon")) r = md_image_applications(argv[2], argv[3]);
    else if (argc == 5 && !strcmp(argv[1], "export-tree")) r = md_image_export_tree(argv[2], argv[3], argv[4]);
    else if ((argc == 4 || (argc == 5 && !strcmp(argv[4], "--replace"))) && !strcmp(argv[1], "resolver"))
        r = md_image_resolver(argv[2], argv[3], argc == 5);
    else if (argc >= 3 && !strcmp(argv[1], "run")) r = md_image_launch(MD_IMAGE_RUN, argc-2, argv+2);
    else if (argc >= 3 && !strcmp(argv[1], "exec")) r = md_image_launch(MD_IMAGE_EXEC, argc-2, argv+2);
    else if (argc >= 3 && !strcmp(argv[1], "login")) r = md_image_launch(MD_IMAGE_LOGIN, argc-2, argv+2);
    else fprintf(stderr, "Usage: image import OCI_LAYOUT NEW_IMAGE (--map-current-user|--preserve-ownership) [--reference TAG] [--layers DIRECTORY] [--blobs DIRECTORY]\n"
        "       image create IMAGE NEW_INSTANCE\n"
        "       image rootfs ARCHIVE NEW_IMAGE\n"
        "       image backup STORE NEW_ARCHIVE\n"
        "       image restore ARCHIVE NEW_INSTANCE\n"
        "       image remove STORE | remove-layer LAYER (caller verifies persistent dependents)\n"
        "       image sources STORE (dependency paths without runtime schema admission)\n"
        "       image relative-sources STORE (prepare source links for an offline tree move)\n"
        "       image relocate-library OLD NEW (move an idle library without copying file bodies)\n"
        "       image inspect IMAGE_OR_INSTANCE\n"
        "       image format (stable persistent namespace format)\n"
        "       image import-version (import semantics for derived image cache keys)\n"
        "       image prepare STORE (update supported metadata before use; busy stores are retained)\n"
        "       image maintain STORE (reclaim detached objects and unused backings; requires idle store)\n"
        "       image exec INSTANCE [OPTIONS] -- COMMAND... | login INSTANCE [OPTIONS] [-- SHELL...]\n"
        "       image run INSTANCE [--user current|UID[:GID]|NAME[:GROUP]] [--cwd PATH] [--entrypoint PROGRAM] [--env KEY=VALUE] [--statistics] [--diagnostics[=signals]]\n"
        "             [--hostname NAME] [--network host|none|bridge|routed] [-p [IP:]HOST:GUEST[/tcp|/udp]]\n"
        "             [--dns IP] [--subnet CIDR] [--ip IPv4] [--ip6 IPv6] [--gateway IP]\n"
        "             [--bind HOST GUEST] [--bind-ro HOST GUEST] [--bind-ro-create HOST GUEST]\n"
        "             [--bind-store-ro STORE GUEST]\n"
        "             [--bind-fuse SOCKET GUEST] [--bind-fuse-ro SOCKET GUEST]\n"
        "             [--owner-fd FD] [-- COMMAND...]\n");
    return r;
}
static int client_message(unsigned phase, int error) {
    struct shroot_client_message message = {SHROOT_CLIENT_MAGIC, phase, error, 0};
    ssize_t n;
    do { n = send(SHROOT_CLIENT_FD, &message, sizeof(message), MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    return n == sizeof(message) ? 0 : n < 0 ? -errno : -EIO;
}
int main(int argc, char **argv) {
    int client = argc > 1 && !strcmp(argv[1], SHROOT_CLIENT_OPTION);
    int r = 0;
    if (client) {
        if (argc < 4) return 1;
        char *end; errno = 0;
        unsigned long count = strtoul(argv[2], &end, 10);
        if (errno || !*argv[2] || *end || count > INT_MAX - 4) return 1;
        int *keep = malloc((count + 1) * sizeof(*keep));
        if (!keep) return 1;
        for (unsigned long i = 0; i <= count; ++i) {
            keep[i] = SHROOT_CLIENT_FD + (int)i;
            if (fcntl(keep[i], F_GETFD) < 0) r = -errno;
        }
        if (!r) r = fcntl(SHROOT_CLIENT_FD, F_SETFD, FD_CLOEXEC) ? -errno : (int)md_process_close_fds(keep, (unsigned)count + 1);
        free(keep);
        if (!r) r = client_message(SHROOT_CLIENT_BEGIN, 0);
        if (r) return 1;
        struct shroot_client_message admission;
        ssize_t n;
        /* EVENT_WAIT: the submitting client retains its child pidfd first.
         * Client disconnect cancels admission without touching the store. */
        do { n = recv(SHROOT_CLIENT_FD, &admission, sizeof(admission), MSG_TRUNC); } while (n < 0 && errno == EINTR);
        if (n != sizeof(admission) || admission.magic != SHROOT_CLIENT_MAGIC
                || admission.phase != SHROOT_CLIENT_ADMIT || admission.error || admission.reserved) return 1;
        unsetenv("SHROOT_IMAGE_OWNER_PID");
        argv[2] = argv[0]; argv += 2; argc -= 2;
    }
    r = execute(argc, argv);
    if (r) fprintf(stderr, "Guest image: %s (errno=%d)\n", strerror(-r), -r);
    if (client && client_message(SHROOT_CLIENT_DONE, r)) return 1;
    return r ? 1 : 0;
}
