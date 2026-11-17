#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "readonly-bind")) {
        char path[256], data[16] = {0};
        if (snprintf(path, sizeof(path), "%s/token", argv[2]) >= (int)sizeof(path)) return 30;
        int fd = open(path, O_RDONLY);
        if (fd < 0 || read(fd, data, sizeof(data)) != 9 || memcmp(data, "read-only", 9)) return 31;
        close(fd);
        fd = open(path, O_WRONLY);
        if (fd >= 0 || errno != EROFS) return 32;
        puts("PASS guest: created readonly attachment, contents and write denial");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "limits")) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur != 128 || limit.rlim_max != 4096) return 20;
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit)) return 21;
        int descriptors[256];
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i) {
            descriptors[i] = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (descriptors[i] < 0) { perror("guest netlink budget"); return 22; }
        }
        for (unsigned i = 0; i < sizeof(descriptors)/sizeof(*descriptors); ++i)
            if (close(descriptors[i])) return 23;
        puts("PASS guest limits: inherited soft/hard, raised soft, independent service budget");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "hold")) {
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
