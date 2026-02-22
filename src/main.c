#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    struct stat file_stat;

    // Get file size
    if (stat(filename, &file_stat) != 0) {
        fprintf(stderr, "Error: Unable to access file '%s'\n", filename);
        return 1;
    }

    // Check file size (100KB = 102400 bytes)
    if (file_stat.st_size >= 102400) {
        fprintf(stderr, "Error: File is too large (must be less than 100KB)\n");
        return 1;
    }

    // Open and read the file
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file '%s'\n", filename);
        return 1;
    }

    // Allocate buffer based on file size
    char *buffer = (char *)malloc(file_stat.st_size + 1);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return 1;
    }

    // Read file into buffer
    size_t bytes_read = fread(buffer, 1, file_stat.st_size, file);
    if (bytes_read != (size_t)file_stat.st_size) {
        fprintf(stderr, "Error: Failed to read file completely\n");
        free(buffer);
        fclose(file);
        return 1;
    }

    // Null-terminate the buffer
    buffer[file_stat.st_size] = '\0';

    // Output the file contents
    printf("%s", buffer);

    // Cleanup
    free(buffer);
    fclose(file);

    return 0;
}