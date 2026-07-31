#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "file.h"
#include "shake.h"
#include "mldsa.h"

static int Q = 8380417;

#define MLDSA_65_SIG_LEN     3309
#define MLDSA_65_LAMBDA_B    48      /* λ/4 bytes for commitment hash */
#define MLDSA_65_GAMMA1_VAL  524288U /* 2^19 */
#define MLDSA_65_GAMMA2_VAL  261888U /* (Q-1)/32 */
#define MLDSA_65_TAU_VAL     49
#define MLDSA_65_OMEGA_VAL   55
#define MLDSA_65_BETA_VAL    196U    /* τ*η = 49*4 */
#define MLDSA_65_W1_BITS_VAL 4       /* bit length of w1 coefficients */
#define MLDSA_65_Z_BYTES_VAL 640     /* (γ1+1)*256/8 = 20*256/8 */
#define MLDSA_65_K_VAL       6
#define MLDSA_65_L_VAL       5

static uint16_t unpack(uint8_t *bytes, size_t position);
static void sample_ntt(const uint8_t *rho, int s, int r, uint32_t *out);
static void ntt_transform(uint32_t *coeffs, uint32_t *out);
static uint32_t ZETA[256] = {1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983};

int mldsa_65_load_public_key(const char *public_key_path, MLDSA_65_PublicKey *out_key) {
	uint8_t *key_bytes = NULL;
	SHAKE256_CTX shake256_ctx;
	uint8_t rho[32];
	uint32_t t1_coeffs[256];
	int i, j;

	if (public_key_path == NULL || out_key == NULL) {
		fprintf(stderr, "Error: Invalid arguments for public key load\n");
		return 1;
	}

    key_bytes = read_file_all(public_key_path, MLDSA_65_KEY_LEN);
    if (key_bytes == NULL) {
		fprintf(stderr, "Error: Unable to read public key file '%s'\n", public_key_path);
		return 1;
    }

    memcpy(out_key->bytes, key_bytes, MLDSA_65_KEY_LEN);
	free(key_bytes);
	shake256_init(&shake256_ctx);
	shake256_update(&shake256_ctx, out_key->bytes, MLDSA_65_KEY_LEN);
	shake256_final(&shake256_ctx, out_key->tr);

	memcpy(rho, out_key->bytes, 32);

	for (i = 0; i < MLDSA_65_K; i++) {
		for (j = 0; j < 256; j++) {
			// Unpack 10-bit value and shift left by 13
			t1_coeffs[j] = ((uint32_t)unpack(out_key->bytes + 32 + i * 320, j) << 13) % Q;
		}
		// Convert to NTT domain
		ntt_transform(t1_coeffs, out_key->t1[i]);
	}

	// Populate matrix A
	for (i = 0; i < MLDSA_65_K; i++) {
		for (j = 0; j < MLDSA_65_L; j++) {
			sample_ntt(rho, j, i, out_key->A[i][j]);
			ntt_transform(out_key->A[i][j], out_key->A[i][j]);
		}
	}

    return 0;
}

static void ntt_pure(uint32_t f[256]) {
	int k = 1;
	for (int len = 128; len >= 1; len >>= 1) {
		for (int start = 0; start < 256; start += 2 * len) {
			uint32_t zeta = ZETA[k++];
			for (int j = start; j < start + len; j++) {
				uint32_t t = (uint64_t)zeta * f[j + len] % (uint32_t)Q;
				f[j + len] = (f[j] + (uint32_t)Q - t) % (uint32_t)Q;
				f[j] = (f[j] + t) % (uint32_t)Q;
			}
		}
	}
}

static void inverse_ntt_pure(uint32_t f[256]) {
	int k = 255;
	for (int len = 1; len <= 128; len <<= 1) {
		for (int start = 0; start < 256; start += 2 * len) {
			uint32_t zeta = ZETA[k--];
			for (int j = start; j < start + len; j++) {
				uint32_t t = f[j];
				f[j] = (t + f[j + len]) % (uint32_t)Q;
				f[j + len] = (uint64_t)zeta * ((f[j + len] + (uint32_t)Q - t) % (uint32_t)Q) % (uint32_t)Q;
			}
		}
	}
	/* scale by n^(-1) mod Q = 8347681 */
	for (int i = 0; i < 256; i++) {
		f[i] = (uint64_t)f[i] * 8347681 % (uint32_t)Q;
	}
}

static void sample_in_ball_impl(const uint8_t *c_tilde, int tau, uint32_t *out) {
	SHAKE256_CTX ctx;
	uint8_t buf[221];
	const uint8_t *s, *j, *j_end;
	int i, bit_idx, bit;

	shake256_init(&ctx);
	shake256_update(&ctx, c_tilde, MLDSA_65_LAMBDA_B);
	shake256_digest(&ctx, buf, 221);

	s = buf;
	j = buf + 8;
	j_end = buf + 221;

	for (i = 0; i < 256; i++) out[i] = 0;

	for (i = 256 - tau; i < 256; i++) {
		while (j < j_end && *j > i) j++;
		if (j >= j_end) break;
		out[i] = out[*j];
		bit_idx = i + tau - 256;
		bit = (s[bit_idx / 8] >> (bit_idx % 8)) & 1;
		out[*j] = bit ? (uint32_t)(Q - 1) : 1;
		j++;
	}
}

static uint32_t unpack_20bit(const uint8_t *buf, int n) {
	uint32_t bit_offset = (uint32_t)n * 20;
	uint32_t byte_offset = bit_offset / 8;
	uint32_t bit_shift = bit_offset % 8;
	uint32_t val = (uint32_t)buf[byte_offset]
	             | ((uint32_t)buf[byte_offset + 1] << 8)
	             | ((uint32_t)buf[byte_offset + 2] << 16);
	return (val >> bit_shift) & 0xFFFFFU;
}

static void decompose_v(uint32_t r, uint32_t gamma2, int *r1_out, int *r0_out) {
	uint32_t m2 = 2 * gamma2;
	int r0 = (int)(r % m2);
	if (r0 > (int)gamma2) r0 -= (int)m2;
	if ((int)r - r0 == Q - 1) {
		*r1_out = 0;
		*r0_out = r0 - 1;
	} else {
		*r1_out = ((int)r - r0) / (int)m2;
		*r0_out = r0;
	}
}

static int use_hint_v(uint32_t w, int h, uint32_t gamma2) {
	int m = (int)((Q - 1) / (2 * gamma2));
	int r1, r0;
	decompose_v(w, gamma2, &r1, &r0);
	if (h == 0) return r1;
	if (r0 > 0) return (r1 + 1) % m;
	return ((r1 - 1) % m + m) % m;
}

static void pack_w1_impl(const int *w1, int bit_length, uint8_t *out) {
	int acc = 0, acc_len = 0;
	size_t out_idx = 0;
	for (int i = 0; i < 256; i++) {
		acc |= w1[i] << acc_len;
		acc_len += bit_length;
		while (acc_len >= 8) {
			out[out_idx++] = (uint8_t)(acc & 0xFF);
			acc >>= 8;
			acc_len -= 8;
		}
	}
	if (acc_len > 0) out[out_idx] = (uint8_t)(acc & 0xFF);
}

int mldsa_65_verify(const MLDSA_65_PublicKey *public_key,
                    const unsigned char *ctx,
                    uint8_t ctx_len,
                    const unsigned char *msg,
                    size_t msg_len,
                    const unsigned char *signature,
                    size_t signature_len) {
	const uint8_t *c_tilde, *sig_z, *sig_h;
	uint32_t z[MLDSA_65_L_VAL][256];
	uint32_t z_hat[MLDSA_65_L_VAL][256];
	int h_hints[MLDSA_65_K_VAL][256];
	uint32_t c_hat[256];
	uint32_t t1_hat[256];
	uint32_t a_poly[256];
	uint32_t w_hat[256];
	uint32_t w_poly[256];
	int w1_row[256];
	uint8_t w1_packed[128]; /* 256 coefficients * 4 bits / 8 */
	SHAKE256_CTX shake_ctx;
	uint8_t mu[64]; /* μ = SHAKE256(tr ‖ 0 ‖ ctx_len ‖ ctx ‖ msg)[64] */
	uint8_t ch_check[MLDSA_65_LAMBDA_B];
	int i, j, k, idx;
	char c;

	if (public_key == NULL || msg == NULL || signature == NULL) return 1;
	if (signature_len != MLDSA_65_SIG_LEN || ctx_len > 255) return 1;

	c_tilde = signature;
	sig_z   = signature + MLDSA_65_LAMBDA_B;
	sig_h   = sig_z + (size_t)MLDSA_65_L_VAL * MLDSA_65_Z_BYTES_VAL;

	/* Unpack z: L polynomials, 20-bit signed (γ1 - raw) */
	for (i = 0; i < MLDSA_65_L_VAL; i++) {
		const uint8_t *zp = sig_z + (size_t)i * MLDSA_65_Z_BYTES_VAL;
		for (j = 0; j < 256; j++) {
			uint32_t raw = unpack_20bit(zp, j);
			z[i][j] = (MLDSA_65_GAMMA1_VAL + (uint32_t)Q - raw) % (uint32_t)Q;
		}
	}

	/* Parse hint vector: ω hint indices followed by K limit bytes */
	memset(h_hints, 0, sizeof(h_hints));
	idx = 0;
	for (i = 0; i < MLDSA_65_K_VAL; i++) {
		int limit = sig_h[MLDSA_65_OMEGA_VAL + i];
		if (limit < idx || limit > MLDSA_65_OMEGA_VAL) return 1;
		int first = idx;
		while (idx < limit) {
			if (idx > first && sig_h[idx - 1] >= sig_h[idx]) return 1;
			h_hints[i][sig_h[idx]] = 1;
			idx++;
		}
	}
	for (i = idx; i < MLDSA_65_OMEGA_VAL; i++) {
		if (sig_h[i] != 0) return 1;
	}

	/* Check ||z||∞ < γ1 - β */
	for (i = 0; i < MLDSA_65_L_VAL; i++) {
		for (j = 0; j < 256; j++) {
			uint32_t v = z[i][j] <= (uint32_t)Q / 2 ? z[i][j] : (uint32_t)Q - z[i][j];
			if (v >= MLDSA_65_GAMMA1_VAL - MLDSA_65_BETA_VAL) return 1;
		}
	}

	/* c_hat = NTT(sample_in_ball(c_tilde)) */
	sample_in_ball_impl(c_tilde, MLDSA_65_TAU_VAL, c_hat);
	ntt_pure(c_hat);

	/* z_hat[i] = NTT(z[i]) */
	for (i = 0; i < MLDSA_65_L_VAL; i++) {
		memcpy(z_hat[i], z[i], 256 * sizeof(uint32_t));
		ntt_pure(z_hat[i]);
	}

	/* Compute μ = SHAKE256(tr ‖ 0x00 ‖ ctx_len ‖ ctx ‖ msg)[64] */
	shake256_init(&shake_ctx);
	shake256_update(&shake_ctx, public_key->tr, SHAKE256_DIGEST_SIZE);
	c = 0;
	shake256_update(&shake_ctx, &c, 1);
	shake256_update(&shake_ctx, &ctx_len, 1);
	shake256_update(&shake_ctx, ctx, ctx_len);
	shake256_update(&shake_ctx, msg, msg_len);
	shake256_digest(&shake_ctx, mu, 64);

	/* Compute SHAKE256(μ ‖ pack(w1)) and compare to c_tilde */
	shake256_init(&shake_ctx);
	shake256_update(&shake_ctx, mu, 64);

	for (i = 0; i < MLDSA_65_K_VAL; i++) {
		/* t1_hat = NTT(unpack_10bit(key) << 13) for row i */
		for (j = 0; j < 256; j++) {
			t1_hat[j] = ((uint32_t)unpack((uint8_t *)(public_key->bytes + 32 + i * 320), j) << 13) % (uint32_t)Q;
		}
		ntt_pure(t1_hat);

		/* w_hat = Σ_j A[i][j] ∘ z_hat[j] */
		memset(w_hat, 0, sizeof(w_hat));
		for (j = 0; j < MLDSA_65_L_VAL; j++) {
			sample_ntt(public_key->bytes, j, i, a_poly);
			for (k = 0; k < 256; k++) {
				w_hat[k] = ((uint64_t)w_hat[k] + (uint64_t)a_poly[k] * z_hat[j][k]) % (uint32_t)Q;
			}
		}
		/* w_hat -= c_hat ∘ t1_hat */
		for (k = 0; k < 256; k++) {
			uint32_t ct = (uint64_t)c_hat[k] * t1_hat[k] % (uint32_t)Q;
			w_hat[k] = (w_hat[k] + (uint32_t)Q - ct) % (uint32_t)Q;
		}

		/* w = INTT(w_hat) */
		memcpy(w_poly, w_hat, sizeof(w_hat));
		inverse_ntt_pure(w_poly);

		/* w1 = use_hint(w, h[i]) */
		for (k = 0; k < 256; k++) {
			w1_row[k] = use_hint_v(w_poly[k], h_hints[i][k], MLDSA_65_GAMMA2_VAL);
		}

		pack_w1_impl(w1_row, MLDSA_65_W1_BITS_VAL, w1_packed);
		shake256_update(&shake_ctx, w1_packed, 128);
	}

	shake256_digest(&shake_ctx, ch_check, MLDSA_65_LAMBDA_B);
	return memcmp(ch_check, c_tilde, MLDSA_65_LAMBDA_B) != 0;
}

static uint16_t unpack(uint8_t *bytes, size_t position) {
    uint32_t val = 0;
    size_t bit_offset = position * 10;
    size_t byte_offset = bit_offset / 8;
    size_t bit_shift = bit_offset % 8;

    val = (bytes[byte_offset] | (bytes[byte_offset + 1] << 8) | (bytes[byte_offset + 2] << 16)) >> bit_shift;
    val &= 0x3FF;
    return val;
}

static uint64_t montgomery_reduce(uint64_t a) {
    uint64_t t = (a * 58728449ULL) & 0x7FFFFFFFFULL;
    t = (a - t * Q) >> 32;
    return t < 0 ? t + Q : t;
}

static uint32_t montgomery_multiply(uint32_t a, uint32_t b) {
    return montgomery_reduce((uint64_t)a * b);
}

static void ntt_transform(uint32_t *coeffs, uint32_t *out) {
    uint32_t f[256];
    memcpy(f, coeffs, 256 * sizeof(uint32_t));

    int k = 1;
    for (int len = 128; len >= 1; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            uint32_t zeta = ZETA[k++];
            for (int j = start; j < start + len; j++) {
                uint32_t t = montgomery_multiply(f[j + len], zeta);
                f[j + len] = (f[j] - t + Q) % Q;
                f[j] = (f[j] + t) % Q;
            }
        }
    }

    memcpy(out, f, 256 * sizeof(uint32_t));
}

static void sample_ntt(const uint8_t *rho, int s, int r, uint32_t *out) {
	SHAKE128_CTX shake128_ctx;
	uint8_t buf[894];
	int a_idx = 0;
	size_t buf_idx = 0;

	shake128_init(&shake128_ctx);
	shake128_update(&shake128_ctx, rho, 32);
	uint8_t indices[2] = {s, r};
	shake128_update(&shake128_ctx, indices, 2);
	shake128_digest(&shake128_ctx, buf, 894);

	while (a_idx < 256) {
		if (buf_idx + 3 > 894) {
			break;
		}
		uint32_t v = (buf[buf_idx] | (buf[buf_idx + 1] << 8) | (buf[buf_idx + 2] << 16)) & 0x7FFFFF;
		buf_idx += 3;
		if (v < Q) {
			out[a_idx++] = v;
		}
	}
}