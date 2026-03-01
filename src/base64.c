#include <stddef.h>
#include <string.h>

void base64_encode(unsigned char hash[32], unsigned char output[44]) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;

    for (i = 0; i < 32; i += 3) {
        unsigned char b1 = hash[i];
        unsigned char b2 = (i + 1 < 32) ? hash[i + 1] : 0;
        unsigned char b3 = (i + 2 < 32) ? hash[i + 2] : 0;

        output[j++] = base64_chars[(b1 >> 2) & 0x3F];
        output[j++] = base64_chars[((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)];
        output[j++] = (i + 1 < 32) ? base64_chars[((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)] : '=';
        output[j++] = (i + 2 < 32) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[j] = '\0';
}

static int decode_base64_char(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

int base64_decode(const char *input, unsigned char *output, size_t *out_len) {
	size_t len = strlen(input);
	size_t i = 0;
	size_t j = 0;
	int val;
	int valb = -8;
	int acc = 0;

	for (i = 0; i < len; ++i) {
		char c = input[i];
		if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
			continue;
		}
		val = decode_base64_char(c);
		if (val < 0) {
			return 1;
		}
		acc = (acc << 6) | val;
		valb += 6;
		if (valb >= 0) {
			output[j++] = (unsigned char)((acc >> valb) & 0xff);
			valb -= 8;
		}
	}

	*out_len = j;
	return 0;
}
