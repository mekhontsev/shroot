#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/capability.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "reserve-large-range")) {
        size_t length = ((size_t)256 << 30) + sysconf(_SC_PAGESIZE);
        void *area = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (area == MAP_FAILED) {
            if (errno == ENOMEM) return 77;
            perror("reserve large address range");
            return 1;
        }
        return munmap(area, length) ? 1 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "fork-exec")) {
        pid_t child = fork();
        if (child < 0) return 12;
        if (!child) {
            char *next[] = {argv[0], argv[2], NULL};
            execv(next[0], next);
            _exit(13);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 14;
        return WEXITSTATUS(status);
    }
    if (argc == 3 && !strcmp(argv[1], "path")) {
        const char *path = getenv("PATH");
        return !path || strcmp(path, argv[2]) ? 40 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "readonly-bind")) {
        char path[256], data[16] = {0};
        if (snprintf(path, sizeof(path), "%s/token", argv[2]) >= (int)sizeof(path)) return 30;
        int fd = open(path, O_RDONLY);
        if (fd < 0 || read(fd, data, sizeof(data)) != 9 || memcmp(data, "read-only", 9)) return 31;
        close(fd);
        fd = open(path, O_WRONLY);
        if (fd >= 0 || errno != EROFS) return 32;
        fd = open(argv[2], O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EROFS) { perror("guest readonly tmpfile"); return 33; }
        puts("PASS guest: created readonly attachment, contents and write denial");
        return 0;
    }
    if ((argc == 3 || argc == 5) && !strcmp(argv[1], "native-tmpfile")) {
        mode_t mask = umask(0077);
        int errors[2] = {0};
        for (unsigned exclusive = 0; exclusive < 2; ++exclusive) {
            int fd = open(argv[2], O_TMPFILE | O_RDWR | O_CLOEXEC | (exclusive ? O_EXCL : 0), 0666);
            errors[exclusive] = fd < 0 ? errno : 0;
            if (argc == 5 && errors[exclusive] != atoi(argv[3 + exclusive])) {
                fprintf(stderr, "temporary file exclusive=%u expected errno=%s actual=%d\n",
                        exclusive, argv[3 + exclusive], errors[exclusive]);
                if (fd >= 0) close(fd);
                return 34;
            }
            /* Bind attachments retain their source filesystem capabilities.
             * Record unsupported O_TMPFILE, not unrelated IO/permission errors. */
            if (fd < 0 && (errno == EOPNOTSUPP || errno == EINVAL || errno == EISDIR)) continue;
            struct stat st;
            if (fd < 0 || fstat(fd, &st)) { perror("guest native tmpfile"); return 34; }
            if (!S_ISREG(st.st_mode) || (st.st_mode & 0777) != 0600 || st.st_nlink
                    || fcntl(fd, F_GETFD) != FD_CLOEXEC) return 35;
            char value = 0;
            if (write(fd, "x", 1) != 1 || pread(fd, &value, 1, 0) != 1 || value != 'x'
                    || close(fd)) return 36;
        }
        umask(mask);
        printf("[%d,%d]\n", errors[0], errors[1]);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "publish-tmpfile")) {
        int dir=open(argv[2],O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        int fd=openat(dir,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600);
        struct stat before,after;
        if (fd<0 || fstat(fd,&before) || before.st_nlink || write(fd,"A",1)!=1) {
            perror("prepare tmpfile"); return 37;
        }
        pid_t child=fork();
        if (!child) {
            char proc[64];
            snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
            if (!linkat(AT_FDCWD,proc,AT_FDCWD,"/native-alias/escaped",AT_SYMLINK_FOLLOW)
                    || errno!=EXDEV) { perror("publish across attachments"); _exit(38); }
            if (!linkat(AT_FDCWD,proc,dir,"nofollow",0)) _exit(38);
            if (!linkat(AT_FDCWD,proc,dir,"token",AT_SYMLINK_FOLLOW) || errno!=EEXIST) {
                perror("publish to occupied name"); _exit(38);
            }
            if (linkat(AT_FDCWD,proc,dir,"published",AT_SYMLINK_FOLLOW)) {
                perror("publish tmpfile"); _exit(39);
            }
            _exit(0);
        }
        int status;
        if (child<0 || waitpid(child,&status,0)!=child || status) return 38;
        if (fstat(fd,&after) || after.st_nlink!=1 || write(fd,"B",1)!=1 ||
                fstatat(dir,"published",&after,AT_SYMLINK_NOFOLLOW) ||
                after.st_ino!=before.st_ino || after.st_dev!=before.st_dev) return 39;
        int exclusive=openat(dir,".",O_TMPFILE|O_EXCL|O_RDWR,0600);
        if (exclusive<0) return 39;
        char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",exclusive);
        if (!linkat(AT_FDCWD,proc,dir,"exclusive",AT_SYMLINK_FOLLOW) || close(exclusive)) return 39;
        int direct=openat(dir,".",O_TMPFILE|O_RDWR,0600);
        struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3};
        struct __user_cap_data_struct caps[2];
        if (direct<0 || syscall(SYS_capget,&header,caps)) return 39;
        int rc=linkat(direct,"",dir,"direct",AT_EMPTY_PATH);
        if (caps[0].effective&(1U<<CAP_DAC_READ_SEARCH)) {
            if (rc || unlinkat(dir,"direct",0)) { perror("privileged empty-path link"); return 39; }
        } else if (!rc || errno!=ENOENT) { perror("unprivileged empty-path link"); return 39; }
        if (fstat(direct,&after) || after.st_nlink || close(direct)) return 39;
        return close(fd) || close(dir);
    }
    if (argc == 2 && !strcmp(argv[1], "limits")) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur != 128 || limit.rlim_max != 4096) return 20;
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit)) return 21;
        int descriptors[256];
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i) {
            descriptors[i] = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (descriptors[i] < 0) {
                fprintf(stderr,"guest netlink budget index=%u errno=%d\n",i,errno);
                perror("guest netlink budget"); return 22;
            }
        }
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i)
            if (close(descriptors[i])) return 23;
        puts("PASS guest limits: inherited soft/hard, raised soft, independent service budget");
        return 0;
    }
    if (argc == 2 && (!strcmp(argv[1], "hold") || !strcmp(argv[1], "hold-owner"))) {
        if (!strcmp(argv[1], "hold-owner")) for (int i = 4; i <= 5; ++i)
            if (fcntl(i, F_GETFD) >= 0 || errno != EBADF) return 41;
        if (fork() < 0) return 10;
        if (write(1, "ready\n", 6) != 6) return 11;
        for (;;) pause();
    }
    if (argc == 2 && !strcmp(argv[1], "exit42")) return 42;
    if (argc != 2 || strcmp(argv[1], "spaces ' ; $(false)")) return 1;
    const char *value = getenv("LIBSHROOT_TEST");
    if (!value || strcmp(value, "retained ' value")) return 2;
    struct stat a, b;
    if (stat("/payload", &a) || stat("/hardlink", &b) || a.st_ino != b.st_ino || a.st_nlink != 2) return 3;
    int fd = open("/link", O_RDONLY);
    char data[64] = {0};
    if (fd < 0 || read(fd, data, sizeof(data)-1) != 17 || strcmp(data, "libshroot payload")) return 4;
    close(fd);
    if (fcntl(123, F_GETFD) >= 0 || errno != EBADF) return 5;
    puts("PASS guest: arguments, environment, metadata and descriptor isolation");
    return 0;
}
