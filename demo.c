/* Realization of block encryption standards AES-128 and AES-256 (FIPS Pub 197)

BSD 2-Clause License

Copyright (c) 2016, George Weigt
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

void test_aes128(void);
void test_aes256(void);
void hextobin(uint8_t *buf, int len, char *str);

int
main(int argc, char *argv[])
{
	aes_init();
	test_aes128();
	test_aes256();
}

#define KEY1 "000102030405060708090a0b0c0d0e0f"
#define PLAIN1 "00112233445566778899aabbccddeeff"
#define CIPHER1 "69c4e0d86a7b0430d8cdb78070b4c55a"

void
test_aes128(void)
{
	int err;
	uint8_t k[16], p[16], c[16], out[16];
	uint32_t w[44], v[44];

	printf("Testing AES-128\n");

	hextobin(k, 16, KEY1);
	hextobin(p, 16, PLAIN1);
	hextobin(c, 16, CIPHER1);

	aes128_expand_key(k, w, v);

	aes128_encrypt_block(w, p, out);

	err = memcmp(c, out, 16);

	if (err) {
		printf("encryption fail\n");
		return;
	}

	aes128_decrypt_block(v, out, out);

	err = memcmp(p, out, 16);

	if (err) {
		printf("decryption fail\n");
		return;
	}

	printf("pass\n");
}

#define KEY2 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define PLAIN2 "00112233445566778899aabbccddeeff"
#define CIPHER2 "8ea2b7ca516745bfeafc49904b496089"

void
test_aes256(void)
{
	int err;
	uint8_t k[32], p[16], c[16], out[16];
	uint32_t w[60], v[60];

	printf("Testing AES-256\n");

	hextobin(k, 32, KEY2);
	hextobin(p, 16, PLAIN2);
	hextobin(c, 16, CIPHER2);

	aes256_expand_key(k, w, v);

	aes256_encrypt_block(w, p, out);

	err = memcmp(c, out, 16);

	if (err) {
		printf("encryption fail\n");
		return;
	}

	aes256_decrypt_block(v, out, out);

	err = memcmp(p, out, 16);

	if (err) {
		printf("decryption fail\n");
		return;
	}

	printf("pass\n");
}

void
hextobin(uint8_t *buf, int len, char *str)
{
	int d, i, n;

	n = strlen(str) / 2;

	if (n > len)
		n = len;

	for (i = 0; i < n; i++) {
		sscanf(str + 2 * i, "%2x", &d);
		buf[i] = d;
	}
}
