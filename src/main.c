#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base64.h"
#include "cjson/cJSON.h"
#include "ecdsa.h"
#include "sha256.h"

static int MAX_FILE_SIZE = 102400;

struct parsedBundle {
    cJSON *bundle;
    cJSON *media_type;
    cJSON *message_signature;
    cJSON *signature;
    cJSON *digest;
};

char *read_bundle(const char* filepath) {
    struct stat file_stat;
    FILE* file;
    char* buffer;
    size_t bytes_read;

    if (stat(filepath, &file_stat) != 0) {
        fprintf(stderr, "Error: Unable to access file '%s'\n", filepath);
        return NULL;
    }

    file = fopen(filepath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file '%s'\n", filepath);
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

int hash_file(char *filepath, SHA256_CTX* ctx) {
    FILE* file;
    char buffer[1024];
    size_t bytes_read;

    file = fopen(filepath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Unable to open file '%s'\n", filepath);
        return 1;
    }

    do {
        bytes_read = fread(buffer, 1, 1024, file);
        sha256_update(ctx, buffer, bytes_read);
    } while (bytes_read > 0);

    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    char* filepath;
    char* bundle;
    struct parsedBundle parsed_bundle;
    SHA256_CTX ctx;
    unsigned char file_hash[32];
    char file_hash_b64[44];
    ECDSA_PublicKey public_key;
    char signature_bytes[72];
    size_t signature_bytes_size;

    memset(&parsed_bundle, 0, sizeof(struct parsedBundle));

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <bundle> <key> <filename>\n", argv[0]);
        return 1;
    }

    filepath = argv[1];
    bundle = read_bundle(filepath);

    if (bundle == NULL) {
        return 1;
    }

    parse_bundle(bundle, &parsed_bundle);
    free(bundle);
    if (parsed_bundle.bundle == NULL) {
        fprintf(stderr, "Error: Failed to parse JSON\n");
        return 1;
    }

    printf("signature from bundle: %s\n", parsed_bundle.signature->valuestring);
    printf("digest from bundle: %s\n", parsed_bundle.digest->valuestring);

    filepath = argv[3];
    sha256_init(&ctx);
    if (hash_file(filepath, &ctx) != 0) {
        cJSON_Delete(parsed_bundle.bundle);
        return 1;
    }
    sha256_final(&ctx, file_hash);

    base64_encode(file_hash, file_hash_b64);

    if (strncmp(file_hash_b64, parsed_bundle.digest->valuestring, 44) == 0) {
        printf("Digest matches\n");
    } else {
        fprintf(stderr, "Error: Digest mismatch\n");
        fprintf(stderr, "Expected: %s\n", parsed_bundle.digest->valuestring);
        fprintf(stderr, "Got: %s\n", file_hash_b64);
        cJSON_Delete(parsed_bundle.bundle);
        return 1;
    }

    if (strlen(parsed_bundle.signature->valuestring) != 96) {
        fprintf(stderr, "Error: bundle signature is incorrect size");
        cJSON_Delete(parsed_bundle.bundle);
        return 1;
    }
    base64_decode(parsed_bundle.signature->valuestring, signature_bytes, &signature_bytes_size);

    filepath = argv[2];
    if (ecdsa_load_public_key_p256(filepath, &public_key) != 0) {
        fprintf(stderr, "Error: unable to load public key");
        cJSON_Delete(parsed_bundle.bundle);
        return 1;
    }
    if (ecdsa_verify_p256(&public_key, file_hash, 32, signature_bytes, signature_bytes_size) != 0) {
        fprintf(stderr, "Error: signature failed to verify");
        cJSON_Delete(parsed_bundle.bundle);
        return 1;
    }

    printf("Signature verified successfully\n");

    // Cleanup
    cJSON_Delete(parsed_bundle.bundle);
    return 0;
}
