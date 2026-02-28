#ifndef BASE64_H_
#define BASE64_H_

void base64_encode(unsigned char hash[32], unsigned char output[44]);
int base64_decode(const char *input, unsigned char *output, size_t *out_len);

#endif /* BASE64_H_ */
