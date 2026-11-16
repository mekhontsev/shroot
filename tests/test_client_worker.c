#define _GNU_SOURCE
#include "client_protocol.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void message(unsigned phase, int error) {
    struct shroot_client_message value = {SHROOT_CLIENT_MAGIC, phase, error, 0};
    assert(send(SHROOT_CLIENT_FD, &value, sizeof(value), MSG_NOSIGNAL) == sizeof(value));
}
int main(int argc, char **argv) {
    assert(argc >= 3 && !strcmp(argv[1], SHROOT_CLIENT_OPTION));
    struct shroot_client_message admission;
    assert(recv(SHROOT_CLIENT_FD, &admission, sizeof(admission), 0) == sizeof(admission));
    assert(admission.magic == SHROOT_CLIENT_MAGIC && admission.phase == SHROOT_CLIENT_ADMIT);
    const char *mode = getenv("SHROOT_TEST_MODE");
    if (mode && !strcmp(mode, "missing")) return 0;
    if (mode && !strcmp(mode, "invalid")) {
        message(SHROOT_CLIENT_DONE, -ENOENT); return 1;
    }
    message(SHROOT_CLIENT_BEGIN, 0);
    if (mode && !strcmp(mode, "duplicate")) {
        message(SHROOT_CLIENT_BEGIN, 0); return 0;
    }
    if (mode && !strcmp(mode, "wait")) {
        assert(!write(1, "", 0));
        assert(write(1, "ready\n", 6) == 6);
        for (;;) pause();
    }
    if (mode && !strcmp(mode, "args")) {
        for (int i = 2; i < argc; ++i) puts(argv[i]);
        message(SHROOT_CLIENT_DONE, 0); return 0;
    }
    if (mode && !strcmp(mode, "launch")) {
        assert(!strcmp(argv[2], "exec"));
        close(SHROOT_CLIENT_FD); return 42;
    }
    if (mode && !strcmp(mode, "incomplete")) return 0;
    if (mode && !strcmp(mode, "error")) { message(SHROOT_CLIENT_DONE, -EBUSY); return 1; }
    assert(!strcmp(argv[2], "format"));
    puts("17"); message(SHROOT_CLIENT_DONE, 0); return 0;
}
