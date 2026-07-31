#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base64.h"
#include "cjson/cJSON.h"
#include "ecdsa.h"
#include "file.h"
#include "mldsa.h"
#include "sha256.h"

struct parsedBundle {
    size_t signature_len;
    char signature_bytes[3309];
    char digest_bytes[32];
};

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int parse_bundle(char* bundle_str, struct parsedBundle* parsed_bundle) {
    const char *expected_media_type = "application/vnd.dev.sigstore.bundle.v0.3+json\0";
    const char *expected_algorithm = "SHA2_256\0";
    const char *expected_payload_type = "application/vnd.in-toto+json\0";
    cJSON *bundle;
    cJSON *media_type;
    cJSON *message_signature;
    cJSON *signature;
    cJSON *digest;
    cJSON *message_digest;
    cJSON *algorithm;
    cJSON *dsse_envelope;
    cJSON *payload_type;
    cJSON *payload;
    cJSON *signatures;
    cJSON *signature_element;
    cJSON *payload_json;
    cJSON *subject;
    cJSON *subject_element;
    cJSON *digest_obj;
    char* payload_decoded;
    size_t payload_decoded_size;
    size_t decode_size;
    size_t i;
    int high, low;

    bundle = cJSON_Parse(bundle_str);
    if (bundle == NULL) {
        return 1;
    }

    media_type = cJSON_GetObjectItemCaseSensitive(bundle, "mediaType");
    if (media_type == NULL || media_type->type != cJSON_String) {
        fprintf(stderr, "Error: Missing or invalid 'mediaType' field\n");
        cJSON_Delete(bundle);
        return 1;
    }
    
    if (strncmp(media_type->valuestring, expected_media_type, strlen(expected_media_type)) != 0) {
        fprintf(stderr, "Error: Invalid mediaType. Expected '%s', got '%s'\n", 
                expected_media_type, media_type->valuestring);
        cJSON_Delete(bundle);
        return 1;
    }

    message_signature = cJSON_GetObjectItemCaseSensitive(bundle, "messageSignature");
    if (message_signature != NULL) {
        // Parse messageSignature
        signature = cJSON_GetObjectItemCaseSensitive(message_signature, "signature");
        if (signature == NULL || signature->type != cJSON_String || strlen(signature->valuestring) > 4412) {
            fprintf(stderr, "Error: Missing or invalid 'messageSignature.signature' field\n");
            cJSON_Delete(bundle);
            return 1;
        }
        base64_decode(signature->valuestring, parsed_bundle->signature_bytes, &parsed_bundle->signature_len);

        message_digest = cJSON_GetObjectItemCaseSensitive(message_signature, "messageDigest");
        if (message_digest == NULL) {
            fprintf(stderr, "Error: Missing 'messageDigest' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        algorithm = cJSON_GetObjectItemCaseSensitive(message_digest, "algorithm");
        if (algorithm == NULL || algorithm->type != cJSON_String) {
            fprintf(stderr, "Error: Missing or invalid 'messageSignature.algorithm' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        if (strncmp(algorithm->valuestring, expected_algorithm, strlen(expected_algorithm)) != 0) {
            fprintf(stderr, "Error: Invalid algorithm. Expected '%s', got '%s'\n", 
                    expected_algorithm, algorithm->valuestring);
            cJSON_Delete(bundle);
            return 1;
        }

        digest = cJSON_GetObjectItemCaseSensitive(message_digest, "digest");
        if (digest == NULL || digest->type != cJSON_String || strlen(digest->valuestring) > 44) {
            fprintf(stderr, "Error: Missing or invalid 'messageSignature.digest' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        base64_decode(digest->valuestring, parsed_bundle->digest_bytes, &decode_size);
    } else {
        // DSSE parsing
        dsse_envelope = cJSON_GetObjectItemCaseSensitive(bundle, "dsseEnvelope");
        if (dsse_envelope == NULL) {
            fprintf(stderr, "Error: unable to find messageSignature or dsseEnvelope\n");
            cJSON_Delete(bundle);
            return 1;
        }

        payload_type = cJSON_GetObjectItemCaseSensitive(dsse_envelope, "payloadType");
        if (payload_type == NULL || (payload_type != NULL && payload_type->type != cJSON_String)) {
            fprintf(stderr, "Error: Missing or invalid 'dsseEnvelope.payloadType' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        if (strncmp(payload_type->valuestring, expected_payload_type, strlen(expected_payload_type)) != 0) {
            fprintf(stderr, "Error: Invalid payload_type. Expected '%s', got '%s'\n", 
                    expected_payload_type, payload_type->valuestring);
            cJSON_Delete(bundle);
            return 1;
        }

        signatures = cJSON_GetObjectItemCaseSensitive(dsse_envelope, "signatures");
        if (signatures == NULL || !cJSON_IsArray(signatures)) {
            fprintf(stderr, "Error: Missing or invalid 'dsseEnvelope.signatures' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        signature_element = cJSON_GetArrayItem(signatures, 0);
        if (signature_element == NULL) {
            fprintf(stderr, "Error: Empty 'signatures' array\n");
            cJSON_Delete(bundle);
            return 1;
        }

        signature = cJSON_GetObjectItemCaseSensitive(signature_element, "sig");
        if (signature == NULL || signature->type != cJSON_String || strlen(signature->valuestring) > 96) {
            fprintf(stderr, "Error: Missing or invalid 'sig' in signature\n");
            cJSON_Delete(bundle);
            return 1;
        }
        base64_decode(signature->valuestring, parsed_bundle->signature_bytes, &parsed_bundle->signature_len);

        // Parse payload
        payload = cJSON_GetObjectItemCaseSensitive(dsse_envelope, "payload");
        if (payload == NULL || payload->type != cJSON_String) {
            fprintf(stderr, "Error: Missing or invalid 'payload' field\n");
            cJSON_Delete(bundle);
            return 1;
        }

        // Decode base64 payload
        payload_decoded_size = strlen(payload->valuestring)*3/4+1;
        payload_decoded = malloc(payload_decoded_size + 1);
        base64_decode(payload->valuestring, payload_decoded, &payload_decoded_size);
        payload_decoded[payload_decoded_size] = '\0';

        // Parse payload JSON
        payload_json = cJSON_Parse(payload_decoded);
        free(payload_decoded);
        if (payload_json == NULL) {
            fprintf(stderr, "Error: Failed to parse payload JSON\n");
            cJSON_Delete(bundle);
            return 1;
        }

        // Get subject array
        subject = cJSON_GetObjectItemCaseSensitive(payload_json, "subject");
        if (subject == NULL || !cJSON_IsArray(subject)) {
            fprintf(stderr, "Error: Missing or invalid 'subject' field in payload\n");
            cJSON_Delete(payload_json);
            cJSON_Delete(bundle);
            return 1;
        }

        // Get first subject element
        subject_element = cJSON_GetArrayItem(subject, 0);
        if (subject_element == NULL) {
            fprintf(stderr, "Error: Empty 'subject' array in payload\n");
            cJSON_Delete(payload_json);
            cJSON_Delete(bundle);
            return 1;
        }

        // Get digest object
        digest_obj = cJSON_GetObjectItemCaseSensitive(subject_element, "digest");
        if (digest_obj == NULL) {
            fprintf(stderr, "Error: Missing 'digest' in subject\n");
            cJSON_Delete(payload_json);
            cJSON_Delete(bundle);
            return 1;
        }

        // Get sha256 field (hex-encoded)
        digest = cJSON_GetObjectItemCaseSensitive(digest_obj, "sha256");
        if (digest == NULL || digest->type != cJSON_String || strlen(digest->valuestring) != 64) {
            fprintf(stderr, "Error: Missing or invalid 'sha256' in digest\n");
            cJSON_Delete(payload_json);
            cJSON_Delete(bundle);
            return 1;
        }

        for (i = 0; i < 32; i++) {
            high = hex_char_to_nibble(digest->valuestring[i * 2]);
            low = hex_char_to_nibble(digest->valuestring[i * 2 + 1]);

            if (high < 0 || low < 0) {
                fprintf(stderr, "Error: Invalid hex in 'sha256' digest\n");
                cJSON_Delete(payload_json);
                cJSON_Delete(bundle);
                return 1;
            }

            parsed_bundle->digest_bytes[i] = (char)((high << 4) | low);
        }

        // Clean up payload JSON
        cJSON_Delete(payload_json);
    }
    cJSON_Delete(bundle);
    return 0;
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
    char* bundle, *file, *filepath;
    size_t file_size;
    struct parsedBundle parsed_bundle;
    SHA256_CTX ctx;
    unsigned char file_hash[32];
    char digest_b64[44];
    ECDSA_PublicKey ecdsa_public_key;
    MLDSA_65_PublicKey mldsa_public_key;

    memset(&parsed_bundle, 0, sizeof(struct parsedBundle));

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <bundle> <key> <filename>\n", argv[0]);
        return 1;
    }

    filepath = argv[1];
    bundle = read_file_all(filepath, 0);

    if (bundle == NULL) {
        return 1;
    }

    if (parse_bundle(bundle, &parsed_bundle) != 0) {
        fprintf(stderr, "Error: Failed to parse JSON\n");
        free(bundle);
        return 1;
    }
    free(bundle);

    filepath = argv[3];
    sha256_init(&ctx);
    if (hash_file(filepath, &ctx) != 0) {
        return 1;
    }
    sha256_final(&ctx, file_hash);

    if (strncmp(file_hash, parsed_bundle.digest_bytes, 32) == 0) {
        printf("Digest matches\n");
    } else {
        fprintf(stderr, "Error: Digest mismatch\n");
        base64_encode(parsed_bundle.digest_bytes, digest_b64);
        fprintf(stderr, "Expected: %s\n", digest_b64);
        base64_encode(file_hash, digest_b64);
        fprintf(stderr, "Got: %s\n", digest_b64);
        return 1;
    }

    filepath = argv[2];
    if (parsed_bundle.signature_len <= 72) {
        if (ecdsa_load_public_key_p256(filepath, &ecdsa_public_key) != 0) {
            fprintf(stderr, "Error: unable to load public key\n");
            return 1;
        }
        if (ecdsa_verify_p256(&ecdsa_public_key, file_hash, 32, parsed_bundle.signature_bytes, 72) != 0) {
            fprintf(stderr, "Error: signature failed to verify\n");
            return 1;
        }
    } else if (parsed_bundle.signature_len == 3309) {
        if (mldsa_65_load_public_key(filepath, &mldsa_public_key) != 0) {
            fprintf(stderr, "Error: unable to load public key\n");
            return 1;
        }
        filepath = argv[3];
        file = read_file_and_len(filepath, &file_size);
        if (mldsa_65_verify(&mldsa_public_key, "", 0, file, file_size, parsed_bundle.signature_bytes, 3309) != 0) {
            free(file);
            fprintf(stderr, "Error: signature failed to verify\n");
            return 1;
        }
        free(file);
    } else {
        fprintf(stderr, "Error: did not recognize signature length\n");
        return 1;
    }

    printf("Signature verified successfully\n");
    return 0;
}
