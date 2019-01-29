/*
 * encrypt.c
 *
 *  Created on: 29 Jan 2019
 *      Author: mrz
 *
 *
 *  Beetle[Light+]
 *  -------------
 *  - r=64
 *  - c=80
 */

#include "crypto_aead.h"


int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,
	unsigned long long mlen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k) {

	return 0;
}

int crypto_aead_decrypt(
	unsigned char *m,
	unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,
	unsigned long long clen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k) {

	return 0;
}

/*
 * shuffle for r=64 (8 bytes)
 */
int shuffle(unsigned char *W) {
	unsigned char W1[4];
	unsigned char W2[4];

	memcpy(W1, W, 4);
	memcpy(W2, W+4, 4);

	printf("%02X %02X %02X %02X\n", W1[0], W1[1], W1[2], W1[3]);

	return 0;
}

int main() {
	unsigned char X[4] = { 0, 1, 2, 3 };

	shuffle(X);

	return 0;
}
