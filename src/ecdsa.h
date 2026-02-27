#ifndef ECDSA_H_
#define ECDSA_H_

#include <stddef.h>
#include <stdint.h>

typedef struct ECDSA_PublicKey {
    uint32_t x[8];
    uint32_t y[8];
} ECDSA_PublicKey;

int ecdsa_load_public_key_p256(const char *public_key_path, ECDSA_PublicKey *out_key);

/* signature must be ASN.1 DER encoded (r, s) */
int ecdsa_verify_p256(const ECDSA_PublicKey *public_key,
                      const unsigned char *hash,
                      size_t hash_len,
                      const unsigned char *signature,
                      size_t signature_len);

int base64_decode(const char *input, unsigned char *output, size_t *out_len);

#endif /* ECDSA_H_ */
