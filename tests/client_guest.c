#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
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
