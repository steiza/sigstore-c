#include <stdint.h>
#include <stddef.h>

#ifndef SHAKE_H_
#define SHAKE_H_

typedef struct SHAKE256_CTX {
    uint64_t state[25];
    uint8_t buffer[136];
    size_t buffer_len;
    int finalized;
} SHAKE256_CTX;

typedef struct SHAKE128_CTX {
    uint64_t state[25];
    uint8_t buffer[168];
    size_t buffer_len;
    int finalized;
} SHAKE128_CTX;

#define SHAKE256_DIGEST_SIZE 64
#define SHAKE128_RATE 168

void shake256_init(SHAKE256_CTX *ctx);
void shake256_update(SHAKE256_CTX *ctx, const uint8_t data[], size_t len);
void shake256_final(SHAKE256_CTX *ctx, uint8_t hash[]);
void shake256_digest(SHAKE256_CTX *ctx, uint8_t *hash, size_t len);

void shake128_init(SHAKE128_CTX *ctx);
void shake128_update(SHAKE128_CTX *ctx, const uint8_t data[], size_t len);
void shake128_digest(SHAKE128_CTX *ctx, uint8_t hash[], size_t len);

#endif /* SHAKE_H_ */