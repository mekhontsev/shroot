#ifndef MD_TERMINAL_CALLS_H
#define MD_TERMINAL_CALLS_H
#include <asm/termbits.h>
#include <asm/ioctls.h>
#include <sys/ioctl.h>
static inline int md_terminal_identity_command(unsigned command) {
    return command==TIOCGPGRP || command==TIOCSPGRP || command==TIOCGSID;
}
#define MD_TERMINAL_ATTRIBUTE_COMMANDS(X) X(TCGETS2) X(TCSETS2) X(TCSETSW2) X(TCSETSF2)
static inline int md_terminal_attributes_command(unsigned command) {
#define MATCH(value) command==(value) ||
    return MD_TERMINAL_ATTRIBUTE_COMMANDS(MATCH) 0;
#undef MATCH
}
long md_terminal_attributes(const unsigned long *);
#endif
