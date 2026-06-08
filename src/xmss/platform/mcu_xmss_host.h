#ifndef MCU_XMSS_HOST_H
#define MCU_XMSS_HOST_H

/* Host-only shims for building the MCU-oriented module on Linux.
 * Only included when `MCU_XMSS_HOST` is defined.
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef SYS_CONSOLE_PRINT
#define SYS_CONSOLE_PRINT(...)            \
    do {                                  \
        printf(__VA_ARGS__);              \
    } while (0)
#endif

static inline uint64_t SYS_TIME_Counter64Get(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static inline uint32_t SYS_TIME_CountToMS(uint64_t counts) {
    return (uint32_t)(counts / 1000000ull);
}

#endif /* MCU_XMSS_HOST_H */
