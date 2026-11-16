#ifndef SHROOT_CLIENT_PROTOCOL_H
#define SHROOT_CLIENT_PROTOCOL_H
#include <stdint.h>

/* Private same-bundle completion channel, never guest syscall traffic. */
#define SHROOT_CLIENT_OPTION "--client-v1"
#define SHROOT_CLIENT_FD 3
#define SHROOT_CLIENT_MAGIC UINT32_C(0x53524831)
enum shroot_client_phase { SHROOT_CLIENT_BEGIN = 1, SHROOT_CLIENT_DONE = 2, SHROOT_CLIENT_ADMIT = 3 };
struct shroot_client_message { uint32_t magic, phase; int32_t error, reserved; };

#endif
