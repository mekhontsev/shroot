#ifndef MD_LWIP_ARCH_CC_H
#define MD_LWIP_ARCH_CC_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "../../src/host_random.h"
#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_PLATFORM_DIAG(message) do { printf message; } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { fprintf(stderr,"lwIP: %s\n",message); abort(); } while (0)
static inline uint32_t md_lwip_random(void) {
    uint32_t value;
    if (md_random_u32(&value)) abort();
    return value;
}
#define LWIP_RAND() md_lwip_random()
#endif
