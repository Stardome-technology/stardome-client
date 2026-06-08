#ifndef APP_UTILS_H
#define APP_UTILS_H

#include <stddef.h>

#define APP_UTILS_OK 0
#define APP_UTILS_ERR_IO -1

/* Minimal host-side file helpers used by `mcu_xmss.c`.
 * Embedded targets typically provide their own implementation.
 */
int app_utils_read_file(const char *path, void *buffer, size_t buffer_size, size_t *bytes_read);
int app_utils_write_file(const char *path, const void *buffer, size_t buffer_size, size_t *bytes_written, int truncate);

#endif /* APP_UTILS_H */
