#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "base64.h"
#include "ecdsa.h"

#define P256_LIMBS 8

typedef struct ECDSA_Point {
	uint32_t x[P256_LIMBS];
	uint32_t y[P256_LIMBS];
	int infinity;
} ECDSA_Point;

static const uint32_t P256_P[P256_LIMBS] = {
	0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
	0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu
};

static const uint32_t P256_N[P256_LIMBS] = {
	0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
	0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu
};

static const uint32_t P256_B[P256_LIMBS] = {
	0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u, 0x651d06b0u,
	0x769886bcu, 0xb3ebbd55u, 0xaa3a93e7u, 0x5ac635d8u
};

static const uint32_t P256_GX[P256_LIMBS] = {
	0xd898c296u, 0xf4a13945u, 0x2deb33a0u, 0x77037d81u,
	0x63a440f2u, 0xf8bce6e5u, 0xe12c4247u, 0x6b17d1f2u
};

static const uint32_t P256_GY[P256_LIMBS] = {
	0x37bf51f5u, 0xcbb64068u, 0x6b315eceu, 0x2bce3357u,
	0x7c0f9e16u, 0x8ee7eb4au, 0xfe1a7f9bu, 0x4fe342e2u
};

static const uint32_t BN_ONE[P256_LIMBS] = {1u,0,0,0,0,0,0,0};
static const uint32_t BN_THREE[P256_LIMBS] = {3u,0,0,0,0,0,0,0};

static void bn_zero(uint32_t *out) {
	memset(out, 0, sizeof(uint32_t) * P256_LIMBS);
}

static void bn_copy(uint32_t *out, const uint32_t *in) {
	memcpy(out, in, sizeof(uint32_t) * P256_LIMBS);
}

static int bn_is_zero(const uint32_t *a) {
	size_t i;

	for (i = 0; i < P256_LIMBS; ++i) {
		if (a[i] != 0) {
			return 0;
		}
	}

	return 1;
}

static int bn_is_even(const uint32_t *a) {
	return (a[0] & 1u) == 0;
}

static int bn_cmp(const uint32_t *a, const uint32_t *b) {
	int i;

	for (i = P256_LIMBS - 1; i >= 0; --i) {
		if (a[i] < b[i]) {
			return -1;
		}
		if (a[i] > b[i]) {
			return 1;
		}
	}

	return 0;
}

static void bn_add_raw(const uint32_t *a, const uint32_t *b, uint32_t *out, uint32_t *carry_out) {
	uint64_t sum;
	uint64_t carry = 0;
	size_t i;

	for (i = 0; i < P256_LIMBS; ++i) {
		sum = (uint64_t)a[i] + b[i] + carry;
		out[i] = (uint32_t)sum;
		carry = sum >> 32;
	}

	if (carry_out != NULL) {
		*carry_out = (uint32_t)carry;
	}
}

static void bn_sub_raw(const uint32_t *a, const uint32_t *b, uint32_t *out, uint32_t *borrow_out) {
	uint64_t diff;
	uint64_t borrow = 0;
	size_t i;

	for (i = 0; i < P256_LIMBS; ++i) {
		diff = (uint64_t)a[i] - b[i] - borrow;
		out[i] = (uint32_t)diff;
		borrow = (diff >> 63) & 1u;
	}

	if (borrow_out != NULL) {
		*borrow_out = (uint32_t)borrow;
	}
}

static int bn_get_bit_512(const uint32_t *in, int bit) {
	int word = bit / 32;
	int offset = bit % 32;

	return (in[word] >> offset) & 1u;
}

static int bn_get_bit_256(const uint32_t *in, int bit) {
	int word = bit / 32;
	int offset = bit % 32;

	return (in[word] >> offset) & 1u;
}

static void bn_mod_512(const uint32_t *in, const uint32_t *mod, uint32_t *out) {
	uint32_t rem[P256_LIMBS + 1];
	int bit;

	memset(rem, 0, sizeof(rem));
	for (bit = 511; bit >= 0; --bit) {
		int i;
		uint32_t carry = 0;
		for (i = 0; i < P256_LIMBS + 1; ++i) {
			uint32_t new_carry = rem[i] >> 31;
			rem[i] = (rem[i] << 1) | carry;
			carry = new_carry;
		}
		rem[0] |= (uint32_t)bn_get_bit_512(in, bit);

		if (rem[P256_LIMBS] != 0 || bn_cmp(rem, mod) >= 0) {
			uint32_t borrow = 0;
			for (i = 0; i < P256_LIMBS; ++i) {
				uint64_t diff = (uint64_t)rem[i] - mod[i] - borrow;
				rem[i] = (uint32_t)diff;
				borrow = (uint32_t)((diff >> 63) & 1u);
			}
			rem[P256_LIMBS] -= borrow;
		}
	}

	bn_copy(out, rem);
}

static void bn_add_mod(const uint32_t *a, const uint32_t *b, const uint32_t *mod, uint32_t *out) {
	uint32_t tmp[16];
	uint32_t carry = 0;

	memset(tmp, 0, sizeof(tmp));
	bn_add_raw(a, b, tmp, &carry);
	tmp[8] = carry;
	bn_mod_512(tmp, mod, out);
}

static void bn_sub_mod(const uint32_t *a, const uint32_t *b, const uint32_t *mod, uint32_t *out) {
	uint32_t tmp[16];
	uint32_t carry = 0;

	if (bn_cmp(a, b) >= 0) {
		bn_sub_raw(a, b, out, NULL);
		return;
	}

	memset(tmp, 0, sizeof(tmp));
	bn_add_raw(a, mod, tmp, &carry);
	tmp[8] = carry;
	{
		uint32_t borrow = 0;
		size_t i;
		for (i = 0; i < 16; ++i) {
			uint64_t bi = (i < P256_LIMBS) ? b[i] : 0u;
			uint64_t diff = (uint64_t)tmp[i] - bi - borrow;
			tmp[i] = (uint32_t)diff;
			borrow = (uint32_t)((diff >> 63) & 1u);
		}
	}
	bn_mod_512(tmp, mod, out);
}

static void bn_shift_right1(uint32_t *a, uint32_t carry_in) {
	int i;
	uint32_t carry = carry_in;

	for (i = P256_LIMBS - 1; i >= 0; --i) {
		uint32_t new_carry = a[i] & 1u;
		a[i] = (a[i] >> 1) | (carry << 31);
		carry = new_carry;
	}
}

static void bn_mul(const uint32_t *a, const uint32_t *b, uint32_t *out) {
	uint32_t tmp[16];
	size_t i;
	size_t j;

	memset(tmp, 0, sizeof(tmp));

	for (i = 0; i < P256_LIMBS; ++i) {
		uint64_t carry = 0;
		for (j = 0; j < P256_LIMBS; ++j) {
			uint64_t sum = (uint64_t)tmp[i + j] + (uint64_t)a[i] * b[j] + carry;
			tmp[i + j] = (uint32_t)sum;
			carry = sum >> 32;
		}
		j = i + P256_LIMBS;
		while (carry != 0 && j < 16) {
			uint64_t sum = (uint64_t)tmp[j] + carry;
			tmp[j] = (uint32_t)sum;
			carry = sum >> 32;
			j++;
		}
	}

	for (i = 0; i < 16; ++i) {
		out[i] = tmp[i];
	}
}

static void bn_mul_mod(const uint32_t *a, const uint32_t *b, const uint32_t *mod, uint32_t *out) {
	uint32_t prod[16];

	bn_mul(a, b, prod);
	bn_mod_512(prod, mod, out);
}

static void bn_sqr_mod(const uint32_t *a, const uint32_t *mod, uint32_t *out) {
	bn_mul_mod(a, a, mod, out);
}

static void bn_mod_inv(const uint32_t *a, const uint32_t *mod, uint32_t *out) {
	uint32_t u[P256_LIMBS];
	uint32_t v[P256_LIMBS];
	uint32_t x1[P256_LIMBS];
	uint32_t x2[P256_LIMBS];

	if (bn_is_zero(a)) {
		bn_zero(out);
		return;
	}

	bn_copy(u, a);
	bn_copy(v, mod);
	bn_zero(x1);
	bn_zero(x2);
	x1[0] = 1;

	while (bn_cmp(u, BN_ONE) != 0 && bn_cmp(v, BN_ONE) != 0) {
		while (bn_is_even(u)) {
			bn_shift_right1(u, 0);
			if (bn_is_even(x1)) {
				bn_shift_right1(x1, 0);
			} else {
				uint32_t tmp[P256_LIMBS];
				uint32_t carry = 0;
				bn_add_raw(x1, mod, tmp, &carry);
				bn_copy(x1, tmp);
				bn_shift_right1(x1, carry);
			}
		}

		while (bn_is_even(v)) {
			bn_shift_right1(v, 0);
			if (bn_is_even(x2)) {
				bn_shift_right1(x2, 0);
			} else {
				uint32_t tmp[P256_LIMBS];
				uint32_t carry = 0;
				bn_add_raw(x2, mod, tmp, &carry);
				bn_copy(x2, tmp);
				bn_shift_right1(x2, carry);
			}
		}

		if (bn_cmp(u, v) >= 0) {
			bn_sub_raw(u, v, u, NULL);
			bn_sub_mod(x1, x2, mod, x1);
		} else {
			bn_sub_raw(v, u, v, NULL);
			bn_sub_mod(x2, x1, mod, x2);
		}
	}

	if (bn_cmp(u, BN_ONE) == 0) {
		bn_copy(out, x1);
		return;
	}

	bn_copy(out, x2);
}

static void bn_from_bytes_be(const unsigned char *in, uint32_t *out) {
	size_t i;

	for (i = 0; i < P256_LIMBS; ++i) {
		size_t idx = (P256_LIMBS - 1 - i) * 4;
		out[i] = ((uint32_t)in[idx] << 24) |
				 ((uint32_t)in[idx + 1] << 16) |
				 ((uint32_t)in[idx + 2] << 8) |
				 (uint32_t)in[idx + 3];
	}
}

static void point_copy(ECDSA_Point *out, const ECDSA_Point *in) {
	bn_copy(out->x, in->x);
	bn_copy(out->y, in->y);
	out->infinity = in->infinity;
}

static void point_double(const ECDSA_Point *p, ECDSA_Point *out) {
	uint32_t lambda[P256_LIMBS];
	uint32_t tmp[P256_LIMBS];
	uint32_t tmp2[P256_LIMBS];
	uint32_t inv[P256_LIMBS];

	if (p->infinity || bn_is_zero(p->y)) {
		out->infinity = 1;
		return;
	}

	bn_sqr_mod(p->x, P256_P, tmp);
	bn_add_mod(tmp, tmp, P256_P, tmp2);
	bn_add_mod(tmp2, tmp, P256_P, tmp2);
	bn_sub_mod(tmp2, BN_THREE, P256_P, tmp2);

	bn_add_mod(p->y, p->y, P256_P, tmp);
	bn_mod_inv(tmp, P256_P, inv);
	bn_mul_mod(tmp2, inv, P256_P, lambda);

	bn_sqr_mod(lambda, P256_P, tmp);
	bn_sub_mod(tmp, p->x, P256_P, tmp);
	bn_sub_mod(tmp, p->x, P256_P, out->x);

	bn_sub_mod(p->x, out->x, P256_P, tmp);
	bn_mul_mod(lambda, tmp, P256_P, tmp2);
	bn_sub_mod(tmp2, p->y, P256_P, out->y);

	out->infinity = 0;
}

static void point_add(const ECDSA_Point *p, const ECDSA_Point *q, ECDSA_Point *out) {
	uint32_t lambda[P256_LIMBS];
	uint32_t tmp[P256_LIMBS];
	uint32_t tmp2[P256_LIMBS];
	uint32_t inv[P256_LIMBS];

	if (p->infinity) {
		point_copy(out, q);
		return;
	}
	if (q->infinity) {
		point_copy(out, p);
		return;
	}

	if (bn_cmp(p->x, q->x) == 0) {
		if (bn_cmp(p->y, q->y) != 0) {
			out->infinity = 1;
			return;
		}
		point_double(p, out);
		return;
	}

	bn_sub_mod(q->y, p->y, P256_P, tmp);
	bn_sub_mod(q->x, p->x, P256_P, tmp2);
	bn_mod_inv(tmp2, P256_P, inv);
	bn_mul_mod(tmp, inv, P256_P, lambda);

	bn_sqr_mod(lambda, P256_P, tmp);
	bn_sub_mod(tmp, p->x, P256_P, tmp);
	bn_sub_mod(tmp, q->x, P256_P, out->x);

	bn_sub_mod(p->x, out->x, P256_P, tmp);
	bn_mul_mod(lambda, tmp, P256_P, tmp2);
	bn_sub_mod(tmp2, p->y, P256_P, out->y);

	out->infinity = 0;
}

static void point_mul_add(const uint32_t *k1,
						  const ECDSA_Point *p1,
						  const uint32_t *k2,
						  const ECDSA_Point *p2,
						  ECDSA_Point *out) {
	ECDSA_Point result;
	ECDSA_Point precomp[4];
	int bit;
	ECDSA_Point tmp;
	int idx;

	result.infinity = 1;
	precomp[0].infinity = 1;
	point_copy(&precomp[1], p1);
	point_copy(&precomp[2], p2);
	point_add(p1, p2, &precomp[3]);

	for (bit = 255; bit >= 0; --bit) {
		if ((255 - bit) % 13 == 0) {
			 printf("Verifying... %d%%\n", (255-bit)/13*5);
		}

		point_double(&result, &tmp);
		point_copy(&result, &tmp);

		idx = (bn_get_bit_256(k1, bit) << 1) | bn_get_bit_256(k2, bit);
		if (idx != 0) {
			point_add(&result, &precomp[idx], &tmp);
			point_copy(&result, &tmp);
		}
	}

	point_copy(out, &result);
}


static char *read_file_all(const char *path, size_t *out_len) {
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
	if (out_len != NULL) {
		*out_len = (size_t)size;
	}
	return buf;
}

static int pem_extract_base64(const char *pem, const char *begin_marker, const char *end_marker, char **out_b64) {
	const char *begin = strstr(pem, begin_marker);
	const char *end = NULL;
	size_t len = 0;
	char *b64 = NULL;
	size_t i = 0;
	size_t j = 0;

	if (begin == NULL) {
		return 1;
	}

	begin += strlen(begin_marker);
	end = strstr(begin, end_marker);
	if (end == NULL) {
		return 1;
	}

	len = (size_t)(end - begin);
	b64 = (char *)malloc(len + 1);
	if (b64 == NULL) {
		return 1;
	}

	for (i = 0; i < len; ++i) {
		char c = begin[i];
		if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
			continue;
		}
		b64[j++] = c;
	}

	b64[j] = '\0';
	*out_b64 = b64;
	return 0;
}

static int der_read_len(const unsigned char *buf, size_t buf_len, size_t *offset, size_t *out_len) {
	unsigned char first;
	size_t len = 0;
	size_t i = 0;

	if (*offset >= buf_len) {
		return 1;
	}

	first = buf[(*offset)++];
	if ((first & 0x80u) == 0) {
		*out_len = first;
		return 0;
	}

	len = first & 0x7fu;
	if (len == 0 || len > 4 || (*offset + len) > buf_len) {
		return 1;
	}

	*out_len = 0;
	for (i = 0; i < len; ++i) {
		*out_len = (*out_len << 8) | buf[(*offset)++];
	}

	return 0;
}

static int der_expect_tag(const unsigned char *buf, size_t buf_len, size_t *offset, unsigned char tag, size_t *out_len) {
	if (*offset >= buf_len || buf[*offset] != tag) {
		return 1;
	}

	(*offset)++;
	return der_read_len(buf, buf_len, offset, out_len);
}

static int der_expect_oid(const unsigned char *buf, size_t buf_len, size_t *offset, const unsigned char *oid, size_t oid_len) {
	size_t len = 0;

	if (der_expect_tag(buf, buf_len, offset, 0x06, &len) != 0) {
		return 1;
	}

	if (len != oid_len || (*offset + len) > buf_len) {
		return 1;
	}

	if (memcmp(buf + *offset, oid, oid_len) != 0) {
		return 1;
	}

	*offset += len;
	return 0;
}

static int parse_spki_public_key(const unsigned char *der, size_t der_len, ECDSA_PublicKey *out_key) {
	size_t offset = 0;
	size_t seq_len = 0;
	size_t alg_len = 0;
	size_t bit_len = 0;
	const unsigned char oid_ec_pub[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
	const unsigned char oid_prime256v1[] = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};

	if (der_expect_tag(der, der_len, &offset, 0x30, &seq_len) != 0) {
		return 1;
	}
	if (offset + seq_len != der_len) {
		return 1;
	}

	if (der_expect_tag(der, der_len, &offset, 0x30, &alg_len) != 0) {
		return 1;
	}
	if (der_expect_oid(der, der_len, &offset, oid_ec_pub, sizeof(oid_ec_pub)) != 0) {
		return 1;
	}
	if (der_expect_oid(der, der_len, &offset, oid_prime256v1, sizeof(oid_prime256v1)) != 0) {
		return 1;
	}

	if (der_expect_tag(der, der_len, &offset, 0x03, &bit_len) != 0) {
		return 1;
	}
	if (bit_len < 1 || (offset + bit_len) > der_len) {
		return 1;
	}
	if (der[offset] != 0x00) {
		return 1;
	}
	offset += 1;
	bit_len -= 1;

	if (bit_len != 65 || der[offset] != 0x04) {
		return 1;
	}

	bn_from_bytes_be(der + offset + 1, out_key->x);
	bn_from_bytes_be(der + offset + 33, out_key->y);
	return 0;
}

static int public_key_on_curve(const ECDSA_PublicKey *key) {
	uint32_t y2[P256_LIMBS];
	uint32_t x2[P256_LIMBS];
	uint32_t x3[P256_LIMBS];
	uint32_t tmp[P256_LIMBS];

	if (bn_cmp(key->x, P256_P) >= 0 || bn_cmp(key->y, P256_P) >= 0) {
		return 0;
	}

	bn_sqr_mod(key->y, P256_P, y2);
	bn_sqr_mod(key->x, P256_P, x2);
	bn_mul_mod(x2, key->x, P256_P, x3);

	bn_add_mod(key->x, key->x, P256_P, tmp);
	bn_add_mod(tmp, key->x, P256_P, tmp);
	bn_sub_mod(x3, tmp, P256_P, x3);
	bn_add_mod(x3, P256_B, P256_P, x3);

	return bn_cmp(y2, x3) == 0;
}

static int parse_ecdsa_signature(const unsigned char *sig, size_t sig_len, uint32_t *out_r, uint32_t *out_s) {
	size_t offset = 0;
	size_t seq_len = 0;
	size_t int_len = 0;

	if (der_expect_tag(sig, sig_len, &offset, 0x30, &seq_len) != 0) {
		return 1;
	}
	if (offset + seq_len > sig_len) {
		return 1;
	}

	if (der_expect_tag(sig, sig_len, &offset, 0x02, &int_len) != 0) {
		return 1;
	}
	if (int_len < 32 || int_len > 33 || (sig[offset] & 0x80u) != 0) {
		return 1;
	}
	memcpy(out_r, sig + offset + (int_len - 32), 32);
	offset += int_len;

	if (der_expect_tag(sig, sig_len, &offset, 0x02, &int_len) != 0) {
		return 1;
	}
	if (int_len < 32 || int_len > 33 || (sig[offset] & 0x80u) != 0) {
		return 1;
	}
	memcpy(out_s, sig + offset + (int_len - 32), 32);

	return 0;
}

int ecdsa_load_public_key_p256(const char *public_key_path, ECDSA_PublicKey *out_key) {
	char *pem = NULL;
	char *b64 = NULL;
	unsigned char *der = NULL;
	size_t der_len = 0;
	int result = 1;

	if (public_key_path == NULL || out_key == NULL) {
		fprintf(stderr, "Error: Invalid arguments for public key load\n");
		return 1;
	}

	pem = read_file_all(public_key_path, NULL);
	if (pem == NULL) {
		fprintf(stderr, "Error: Unable to read public key file '%s'\n", public_key_path);
		return 1;
	}

	if (pem_extract_base64(pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", &b64) != 0) {
		fprintf(stderr, "Error: Unsupported PEM format (expected PUBLIC KEY)\n");
		free(pem);
		return 1;
	}

	der = (unsigned char *)malloc(strlen(b64));
	if (der == NULL) {
		fprintf(stderr, "Error: Memory allocation failed\n");
		free(b64);
		free(pem);
		return 1;
	}

	if (base64_decode(b64, der, &der_len) != 0) {
		fprintf(stderr, "Error: Failed to decode base64 key\n");
		free(der);
		free(b64);
		free(pem);
		return 1;
	}

	if (parse_spki_public_key(der, der_len, out_key) != 0) {
		fprintf(stderr, "Error: Failed to parse P-256 public key\n");
		goto cleanup;
	}
	if (!public_key_on_curve(out_key)) {
		fprintf(stderr, "Error: Public key is not on P-256 curve\n");
		goto cleanup;
	}

	result = 0;

cleanup:
	free(der);
	free(b64);
	free(pem);
	return result;
}

int ecdsa_verify_p256(const ECDSA_PublicKey *public_key,
					  const unsigned char *hash,
					  size_t hash_len,
					  const unsigned char *signature,
					  size_t signature_len) {
	uint32_t r[P256_LIMBS];
	uint32_t s[P256_LIMBS];
	uint32_t e[P256_LIMBS];
	uint32_t w[P256_LIMBS];
	uint32_t u1[P256_LIMBS];
	uint32_t u2[P256_LIMBS];
	ECDSA_Point g;
	ECDSA_Point q;
	ECDSA_Point sum;
	uint32_t x_mod_n[P256_LIMBS];
	uint32_t input[16];
	size_t i;

	if (public_key == NULL || hash == NULL || signature == NULL) {
		fprintf(stderr, "Error: Invalid arguments to ECDSA verify\n");
		return -1;
	}

	if (hash_len != 32) {
		fprintf(stderr, "Error: Hash length must be 32 bytes for SHA-256\n");
		return -1;
	}

	if (parse_ecdsa_signature(signature, signature_len, r, s) != 0) {
		fprintf(stderr, "Error: Invalid ECDSA signature format\n");
		return -1;
	}

	if (bn_is_zero(r) || bn_is_zero(s) || bn_cmp(r, P256_N) >= 0 || bn_cmp(s, P256_N) >= 0) {
		fprintf(stderr, "Error: ECDSA signature values out of range\n");
		return 0;
	}

	bn_from_bytes_be(hash, e);
	bn_mod_inv(s, P256_N, w);
	bn_mul_mod(e, w, P256_N, u1);
	bn_mul_mod(r, w, P256_N, u2);

	bn_copy(g.x, P256_GX);
	bn_copy(g.y, P256_GY);
	g.infinity = 0;

	bn_copy(q.x, public_key->x);
	bn_copy(q.y, public_key->y);
	q.infinity = 0;

	point_mul_add(u1, &g, u2, &q, &sum);

	if (sum.infinity) {
		return 0;
	}

	memset(input, 0, sizeof(input));
	for (i = 0; i < 8; i++) {
		input[i] = sum.x[i];
	}

	bn_mod_512(input, P256_N, x_mod_n);

	if (bn_cmp(x_mod_n, r) == 0) {
		return 1;
	}

	return 0;
}
