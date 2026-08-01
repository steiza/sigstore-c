#ifndef MLDSA_H_
#define MLDSA_H_

#include <stddef.h>
#include <stdint.h>

#include "shake.h"

#define MLDSA_65_KEY_LEN 1952
#define MLDSA_65_K 6
#define MLDSA_65_L 5

typedef struct MLDSA_65_PublicKey {
    uint8_t bytes[MLDSA_65_KEY_LEN];
    uint8_t tr[SHAKE256_DIGEST_SIZE];
} MLDSA_65_PublicKey;

int mldsa_65_load_public_key(const char *public_key_path, MLDSA_65_PublicKey *out_key);

int mldsa_65_verify(const MLDSA_65_PublicKey *public_key,
                    const unsigned char *ctx,
                    uint8_t ctx_len,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *signature,
                    size_t signature_len);

#endif /* MLDSA_H_ */
