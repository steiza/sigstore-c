#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "file.h"

char *read_file_all(const char *path, size_t expected_len) {
    size_t size;
    char *buf = NULL;

    buf = read_file_and_len(path, &size);
    if (expected_len != 0 && size != expected_len) {
        if (size != 0) {
            free(buf);
        }
        return NULL;
    }

    return buf;
}

char *read_file_and_len(const char* path, size_t *size) {
    FILE *file = NULL;
    size_t file_size = 0;
    char *buf = NULL;

    if (size != NULL) {
        *size = 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }

    buf = (char *)malloc((size_t)file_size + 1);
    if (buf == NULL) {
        fclose(file);
        return NULL;
    }

    if (fread(buf, 1, (size_t)file_size, file) != (size_t)file_size) {
        free(buf);
        fclose(file);
        return NULL;
    }

    buf[file_size] = '\0';
    fclose(file);
    if (size != NULL) {
        *size = file_size;
    }
    return buf;
}
