#include "app_utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int app_utils_read_file(const char *path, void *buffer, size_t buffer_size, size_t *bytes_read) {
    if (!path || !buffer || buffer_size == 0) {
        if (bytes_read) *bytes_read = 0;
        return APP_UTILS_ERR_IO;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (bytes_read) *bytes_read = 0;
        return APP_UTILS_ERR_IO;
    }

    size_t n = fread(buffer, 1, buffer_size, f);
    int read_err = ferror(f);
    fclose(f);

    if (bytes_read) *bytes_read = n;

    if (read_err) {
        return APP_UTILS_ERR_IO;
    }

    return APP_UTILS_OK;
}

int app_utils_write_file(const char *path, const void *buffer, size_t buffer_size, size_t *bytes_written, int truncate) {
    if (!path || !buffer || buffer_size == 0) {
        if (bytes_written) *bytes_written = 0;
        return APP_UTILS_ERR_IO;
    }

    const char *mode = truncate ? "wb" : "ab";

    FILE *f = fopen(path, mode);
    if (!f) {
        if (bytes_written) *bytes_written = 0;
        return APP_UTILS_ERR_IO;
    }

    size_t n = fwrite(buffer, 1, buffer_size, f);
    int write_err = ferror(f);
    fclose(f);

    if (bytes_written) *bytes_written = n;

    if (write_err || n != buffer_size) {
        return APP_UTILS_ERR_IO;
    }

    return APP_UTILS_OK;
}
