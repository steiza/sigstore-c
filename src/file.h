#ifndef FILE_H_
#define FILE_H_

#include <stddef.h>

char *read_file_all(const char *path, size_t out_len);
char *read_file_and_len(const char* path, size_t *size);

#endif /* FILE_H_ */
