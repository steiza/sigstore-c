#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

char *read_file_all(const char *path, size_t expected_len) {
	FILE *file = NULL;
	long size = 0;
	char *buf = NULL;

	file = fopen(path, "rb");
	if (file == NULL) {
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return NULL;
	}

	size = ftell(file);
	if (size < 0) {
		fclose(file);
		return NULL;
	}
	if (expected_len != 0 && size != expected_len) {
        fclose(file);
        return NULL;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return NULL;
	}

	buf = (char *)malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(file);
		return NULL;
	}

	if (fread(buf, 1, (size_t)size, file) != (size_t)size) {
		free(buf);
		fclose(file);
		return NULL;
	}

	buf[size] = '\0';
	fclose(file);
	return buf;
}

