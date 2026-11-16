#ifndef MD_SIGNAL_ABI_H
#define MD_SIGNAL_ABI_H
#include <signal.h>
/* Guest/kernel numbering is independent of the host libc's reserved signals. */
#define MD_SIGRTMIN 32

/* Linux si_code ABI. Some libcs omit the UAPI names and range bounds. */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#ifndef NSIGILL
#define NSIGILL 11
#endif
#ifndef NSIGFPE
#define NSIGFPE 15
#endif
#ifndef NSIGSEGV
#define NSIGSEGV 10
#endif
#ifndef NSIGBUS
#define NSIGBUS 5
#endif
#ifndef NSIGTRAP
#define NSIGTRAP 6
#endif
#ifndef NSIGCHLD
#define NSIGCHLD 6
#endif
#ifndef NSIGPOLL
#define NSIGPOLL 6
#endif
#ifndef NSIGSYS
#define NSIGSYS 2
#endif
#endif
