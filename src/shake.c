#include "shake.h"

#include <string.h>

#define SHAKE256_RATE 136
#define SHAKE128_RATE 168
#define SHAKE256_ROUNDS 24

#define ROTL64(x, n) ((n) == 0u ? (x) : (((x) << (n)) | ((x) >> (64u - (n)))))

static const uint64_t KECCAKF_ROUND_CONSTANTS[SHAKE256_ROUNDS] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned int KECCAKF_ROTATION[25] = {
	0u, 1u, 62u, 28u, 27u,
	36u, 44u, 6u, 55u, 20u,
	3u, 10u, 43u, 25u, 39u,
	41u, 45u, 15u, 21u, 8u,
	18u, 2u, 61u, 56u, 14u
};

static const unsigned int KECCAKF_PI[25] = {
	0u, 10u, 20u, 5u, 15u,
	16u, 1u, 11u, 21u, 6u,
	7u, 17u, 2u, 12u, 22u,
	23u, 8u, 18u, 3u, 13u,
	14u, 24u, 9u, 19u, 4u
};

static void keccakf(uint64_t state[25]) {
	unsigned int round;

	for (round = 0; round < SHAKE256_ROUNDS; ++round) {
		uint64_t c[5];
		uint64_t d[5];
		uint64_t b[25];
		unsigned int x;
		unsigned int y;

		for (x = 0; x < 5u; ++x) {
			c[x] = state[x] ^ state[x + 5u] ^ state[x + 10u] ^ state[x + 15u] ^ state[x + 20u];
		}

		for (x = 0; x < 5u; ++x) {
			d[x] = c[(x + 4u) % 5u] ^ ROTL64(c[(x + 1u) % 5u], 1u);
		}

		for (x = 0; x < 5u; ++x) {
			for (y = 0; y < 25u; y += 5u) {
				state[x + y] ^= d[x];
			}
		}

		for (x = 0; x < 25u; ++x) {
			b[KECCAKF_PI[x]] = ROTL64(state[x], KECCAKF_ROTATION[x]);
		}

		for (y = 0; y < 25u; y += 5u) {
			state[y] = b[y] ^ ((~b[y + 1u]) & b[y + 2u]);
			state[y + 1u] = b[y + 1u] ^ ((~b[y + 2u]) & b[y + 3u]);
			state[y + 2u] = b[y + 2u] ^ ((~b[y + 3u]) & b[y + 4u]);
			state[y + 3u] = b[y + 3u] ^ ((~b[y + 4u]) & b[y]);
			state[y + 4u] = b[y + 4u] ^ ((~b[y]) & b[y + 1u]);
		}

		state[0] ^= KECCAKF_ROUND_CONSTANTS[round];
	}
}

static void absorb_block(SHAKE256_CTX *ctx, const uint8_t block[SHAKE256_RATE]) {
	size_t i;

	for (i = 0; i < (SHAKE256_RATE / 8u); ++i) {
		uint64_t lane = 0;
		size_t j;

		for (j = 0; j < 8u; ++j) {
			lane |= ((uint64_t)block[i * 8u + j]) << (8u * j);
		}

		ctx->state[i] ^= lane;
	}

	keccakf(ctx->state);
}

static void squeeze_bytes(const uint64_t state[25], uint8_t out[SHAKE256_RATE]) {
	size_t i;

	for (i = 0; i < (SHAKE256_RATE / 8u); ++i) {
		uint64_t lane = state[i];
		size_t j;

		for (j = 0; j < 8u; ++j) {
			out[i * 8u + j] = (uint8_t)((lane >> (8u * j)) & 0xffu);
		}
	}
}

void shake256_init(SHAKE256_CTX *ctx) {
	memset(ctx, 0, sizeof(*ctx));
}

void shake256_update(SHAKE256_CTX *ctx, const uint8_t data[], size_t len) {
	size_t offset = 0;

	if (ctx->finalized != 0) {
		return;
	}

	while (offset < len) {
		size_t space = SHAKE256_RATE - ctx->buffer_len;
		size_t take = len - offset;

		if (take > space) {
			take = space;
		}

		memcpy(&ctx->buffer[ctx->buffer_len], &data[offset], take);
		ctx->buffer_len += take;
		offset += take;

		if (ctx->buffer_len == SHAKE256_RATE) {
			absorb_block(ctx, ctx->buffer);
			ctx->buffer_len = 0;
		}
	}
}

void shake256_final(SHAKE256_CTX *ctx, uint8_t hash[]) {
	size_t produced = 0;
	uint8_t block[SHAKE256_RATE];

	if (ctx->finalized == 0) {
		memset(&ctx->buffer[ctx->buffer_len], 0, SHAKE256_RATE - ctx->buffer_len);
		/* SHAKE domain separation byte with Keccak multi-rate padding. */
		ctx->buffer[ctx->buffer_len] ^= 0x1fu;
		ctx->buffer[SHAKE256_RATE - 1u] ^= 0x80u;
		absorb_block(ctx, ctx->buffer);
		ctx->buffer_len = 0;
		ctx->finalized = 1;
	}

	while (produced < SHAKE256_DIGEST_SIZE) {
		size_t remaining = SHAKE256_DIGEST_SIZE - produced;
		size_t take = remaining;

		if (take > SHAKE256_RATE) {
			take = SHAKE256_RATE;
		}

		squeeze_bytes(ctx->state, block);
		memcpy(&hash[produced], block, take);
		produced += take;

		if (produced < SHAKE256_DIGEST_SIZE) {
			keccakf(ctx->state);
		}
	}
}

static void absorb_block_128(SHAKE128_CTX *ctx, const uint8_t block[SHAKE128_RATE]) {
	size_t i;

	for (i = 0; i < (SHAKE128_RATE / 8u); ++i) {
		uint64_t lane = 0;
		size_t j;

		for (j = 0; j < 8u; ++j) {
			lane |= ((uint64_t)block[i * 8u + j]) << (8u * j);
		}

		ctx->state[i] ^= lane;
	}

	keccakf(ctx->state);
}

static void squeeze_bytes_128(const uint64_t state[25], uint8_t out[SHAKE128_RATE]) {
	size_t i;

	for (i = 0; i < (SHAKE128_RATE / 8u); ++i) {
		uint64_t lane = state[i];
		size_t j;

		for (j = 0; j < 8u; ++j) {
			out[i * 8u + j] = (uint8_t)((lane >> (8u * j)) & 0xffu);
		}
	}
}

void shake256_digest(SHAKE256_CTX *ctx, uint8_t *hash, size_t len) {
	size_t produced = 0;
	uint8_t block[SHAKE256_RATE];

	if (ctx->finalized == 0) {
		memset(&ctx->buffer[ctx->buffer_len], 0, SHAKE256_RATE - ctx->buffer_len);
		ctx->buffer[ctx->buffer_len] ^= 0x1fu;
		ctx->buffer[SHAKE256_RATE - 1u] ^= 0x80u;
		absorb_block(ctx, ctx->buffer);
		ctx->buffer_len = 0;
		ctx->finalized = 1;
	}

	while (produced < len) {
		size_t remaining = len - produced;
		size_t take = remaining < SHAKE256_RATE ? remaining : SHAKE256_RATE;
		squeeze_bytes(ctx->state, block);
		memcpy(&hash[produced], block, take);
		produced += take;
		if (produced < len) {
			keccakf(ctx->state);
		}
	}
}

void shake128_init(SHAKE128_CTX *ctx) {
	memset(ctx, 0, sizeof(*ctx));
}

void shake128_update(SHAKE128_CTX *ctx, const uint8_t data[], size_t len) {
	size_t offset = 0;

	if (ctx->finalized != 0) {
		return;
	}

	while (offset < len) {
		size_t space = SHAKE128_RATE - ctx->buffer_len;
		size_t take = len - offset;

		if (take > space) {
			take = space;
		}

		memcpy(&ctx->buffer[ctx->buffer_len], &data[offset], take);
		ctx->buffer_len += take;
		offset += take;

		if (ctx->buffer_len == SHAKE128_RATE) {
			absorb_block_128(ctx, ctx->buffer);
			ctx->buffer_len = 0;
		}
	}
}

void shake128_digest(SHAKE128_CTX *ctx, uint8_t hash[], size_t len) {
	size_t produced = 0;
	uint8_t block[SHAKE128_RATE];

	if (ctx->finalized == 0) {
		memset(&ctx->buffer[ctx->buffer_len], 0, SHAKE128_RATE - ctx->buffer_len);
		/* SHAKE domain separation byte with Keccak multi-rate padding. */
		ctx->buffer[ctx->buffer_len] ^= 0x1fu;
		ctx->buffer[SHAKE128_RATE - 1u] ^= 0x80u;
		absorb_block_128(ctx, ctx->buffer);
		ctx->buffer_len = 0;
		ctx->finalized = 1;
	}

	while (produced < len) {
		size_t remaining = len - produced;
		size_t take = remaining;

		if (take > SHAKE128_RATE) {
			take = SHAKE128_RATE;
		}

		squeeze_bytes_128(ctx->state, block);
		memcpy(&hash[produced], block, take);
		produced += take;

		if (produced < len) {
			keccakf(ctx->state);
		}
	}
}