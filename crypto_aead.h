/*
 * crypto_aead.h
 *
 *  Created on: 29 Jan 2019
 *      Author: mrz
 */

#ifndef CRYPTO_AEAD_H_
#define CRYPTO_AEAD_H_

#include <stdio.h>

int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,
	unsigned long long mlen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
);

int crypto_aead_decrypt(
	unsigned char *m,
	unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,
	unsigned long long clen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
);

#endif /* CRYPTO_AEAD_H_ */
