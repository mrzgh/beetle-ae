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
 * W is 8 bytes
 */
int shuffle(unsigned char *W) {
	unsigned char W1[4];
	unsigned char W2[4];
	unsigned temp[4];

	memcpy(W1, W, 4);
	memcpy(W2, W+4, 4);

	printf("%02X %02X %02X %02X\n", W1[0], W1[1], W1[2], W1[3]);
	printf("%02X %02X %02X %02X\n", W2[0], W2[1], W2[2], W2[3]);

	memcpy(temp, W2, 4);

	W2[0] ^= W1[0];
	W2[1] ^= W1[1];
	W2[2] ^= W1[2];
	W2[3] ^= W1[3];
	memcpy(W1, temp, 4);

	printf("%02X %02X %02X %02X\n", W1[0], W1[1], W1[2], W1[3]);
	printf("%02X %02X %02X %02X\n", W2[0], W2[1], W2[2], W2[3]);

	memcpy(W, W1, 4);
	memcpy(W+4, W2, 4);

	return 0;
}

/*
 * I1 and I2 are r=64 bits (8 bytes)
 */
int rho(unsigned char *I1, unsigned char *I2) {
	unsigned char temp[8];
	unsigned char O1[8];
	unsigned char O2[8];
	int i;

	printf("I1 = \n"); for (i=0; i<8; i++) printf("%02X ", I1[i]); printf("\n");
	printf("I2 = \n"); for (i=0; i<8; i++) printf("%02X ", I2[i]); printf("\n");


	memcpy(temp, I1, 8);

	shuffle(I1);

	for (i=0; i<8; i++) O1[i] = I1[i] ^ temp[i];
	for (i=0; i<8; i++) O2[i] = I2[i] ^ temp[i];

	memcpy(I1, O1, 4);
	memcpy(I2, O2, 4);

	printf("O1 = \n"); for (i=0; i<8; i++) printf("%02X ", O1[i]); printf("\n");
	printf("O2 = \n"); for (i=0; i<8; i++) printf("%02X ", O2[i]); printf("\n");

	return 0;
}

int main() {
	unsigned char X[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned char Y[8] = { 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

	//shuffle(X);
	//printf("%02X %02X %02X %02X\n", X[0], X[1], X[2], X[3]);
	//printf("%02X %02X %02X %02X\n", X[4], X[5], X[6], X[7]);

	rho(X, Y);

	return 0;
}
