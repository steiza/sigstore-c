#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "cjson/cJSON.h"

static int MAX_FILE_SIZE = 102400;

struct parsedBundle {
    cJSON *bundle;
    cJSON *media_type;
    cJSON *message_signature;
    cJSON *signature;
    cJSON *digest;
};

char *read_bundle(const char* filename) {
    struct stat file_stat;
    FILE* file;
    char* buffer;
    size_t bytes_read;

    if (stat(filename, &file_stat) != 0) {
        fprintf(stderr, "Error: Unable to access file '%s'\n", filename);
        return NULL;
    }

    if (file_stat.st_size >= MAX_FILE_SIZE) {
        fprintf(stderr, "Error: File is too large (must be less than 100KB)\n");
        return NULL;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file '%s'\n", filename);
        return NULL;
    }

    buffer = (char *)malloc(file_stat.st_size + 1);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    bytes_read = fread(buffer, 1, file_stat.st_size, file);
    if (bytes_read != (size_t)file_stat.st_size) {
        fprintf(stderr, "Error: Failed to read file completely\n");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

void parse_bundle(char* bundle, struct parsedBundle* parsed_bundle) {
    const char *expected_media_type = "application/vnd.dev.sigstore.bundle.v0.3+json\0";
    const char *expected_algorithm = "SHA2_256\0";
    cJSON *message_digest;
    cJSON *algorithm;

    parsed_bundle->bundle = cJSON_Parse(bundle);
    if (parsed_bundle->bundle == NULL) {
        return;
    }

    parsed_bundle->media_type = cJSON_GetObjectItemCaseSensitive(parsed_bundle->bundle, "mediaType");
    if (parsed_bundle->media_type == NULL || parsed_bundle->media_type->type != cJSON_String) {
        fprintf(stderr, "Error: Missing or invalid 'mediaType' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }
    
    if (strncmp(parsed_bundle->media_type->valuestring, expected_media_type, strlen(expected_media_type)) != 0) {
        fprintf(stderr, "Error: Invalid mediaType. Expected '%s', got '%s'\n", 
                expected_media_type, parsed_bundle->media_type->valuestring);
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }

    parsed_bundle->message_signature = cJSON_GetObjectItemCaseSensitive(parsed_bundle->bundle, "messageSignature");
    if (parsed_bundle->message_signature == NULL) {
        fprintf(stderr, "Error: Missing 'messageSignature' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }

    parsed_bundle->signature = cJSON_GetObjectItemCaseSensitive(parsed_bundle->message_signature, "signature");
    if (parsed_bundle->signature == NULL || parsed_bundle->signature->type != cJSON_String) {
        fprintf(stderr, "Error: Missing or invalid 'messageSignature.signature' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }

    message_digest = cJSON_GetObjectItemCaseSensitive(parsed_bundle->message_signature, "messageDigest");
    if (message_digest == NULL) {
        fprintf(stderr, "Error: Missing 'messageDigest' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }

    algorithm = cJSON_GetObjectItemCaseSensitive(message_digest, "algorithm");
    if (algorithm == NULL || algorithm->type != cJSON_String) {
        fprintf(stderr, "Error: Missing or invalid 'messageSignature.algorithm' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }


    if (strncmp(algorithm->valuestring, expected_algorithm, strlen(expected_algorithm)) != 0) {
        fprintf(stderr, "Error: Invalid algorithm. Expected '%s', got '%s'\n", 
                expected_algorithm, algorithm->valuestring);
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }

    parsed_bundle->digest = cJSON_GetObjectItemCaseSensitive(message_digest, "digest");
    if (parsed_bundle->digest == NULL || parsed_bundle->digest->type != cJSON_String) {
        fprintf(stderr, "Error: Missing or invalid 'messageSignature.digest' field\n");
        cJSON_Delete(parsed_bundle->bundle);
        parsed_bundle->bundle = NULL;
        return;
    }
}

int main(int argc, char *argv[]) {
    char* filename;
    char* bundle;
    struct parsedBundle parsed_bundle;

    memset(&parsed_bundle, 0, sizeof(struct parsedBundle));

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    filename = argv[1];
    bundle = read_bundle(filename);

    if (bundle == NULL) {
        return 1;
    }

    parse_bundle(bundle, &parsed_bundle);
    free(bundle);
    if (parsed_bundle.bundle == NULL) {
        fprintf(stderr, "Error: Failed to parse JSON\n");
        return 1;
    }

    printf("signature: %s\n", parsed_bundle.signature->valuestring);
    printf("digest: %s\n", parsed_bundle.digest->valuestring);

    // Cleanup
    cJSON_Delete(parsed_bundle.bundle);

    return 0;
}