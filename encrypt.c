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

	//printf("%02X %02X %02X %02X\n", W1[0], W1[1], W1[2], W1[3]);
	//printf("%02X %02X %02X %02X\n", W2[0], W2[1], W2[2], W2[3]);

	memcpy(temp, W2, 4);

	W2[0] ^= W1[0];
	W2[1] ^= W1[1];
	W2[2] ^= W1[2];
	W2[3] ^= W1[3];
	memcpy(W1, temp, 4);

	//printf("%02X %02X %02X %02X\n", W1[0], W1[1], W1[2], W1[3]);
	//printf("%02X %02X %02X %02X\n", W2[0], W2[1], W2[2], W2[3]);

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

	//printf("I1 = \n"); for (i=0; i<8; i++) printf("%02X ", I1[i]); printf("\n");
	//printf("I2 = \n"); for (i=0; i<8; i++) printf("%02X ", I2[i]); printf("\n");


	memcpy(temp, I1, 8);

	shuffle(I1);

	for (i=0; i<8; i++) O1[i] = I1[i] ^ temp[i];
	for (i=0; i<8; i++) O2[i] = I2[i] ^ temp[i];

	memcpy(I1, O1, 4);
	memcpy(I2, O2, 4);

	//printf("O1 = \n"); for (i=0; i<8; i++) printf("%02X ", O1[i]); printf("\n");
	//printf("O2 = \n"); for (i=0; i<8; i++) printf("%02X ", O2[i]); printf("\n");

	return 0;
}


/*
 * S: b-bit state (b=144 bits / 18 bytes)
 * N: r-bit nonce (r=64 bits / 8 bytes)
 * K: b-bit key (b=144 bits / 18 bytes)
 */
int beetle_light_init(unsigned char *S, unsigned char *N, unsigned char *K) {
	int i;
	unsigned char K1[8];
	unsigned char K2[10];

	printf("\nbeetle_light_init\n---\n");

	// copy the first 8 bytes of K to K1
	memcpy(K1, K, 8);

	// copy the last 10 bytes of K to K2
	memcpy(K2, K+8, 10);

	// XOR N with K1 and put back in K1
	for (i=0; i<8; i++) K1[i] ^= N[i];

	// copy the above result as the state S
	memcpy(S, K1, 8);
	memcpy(S+8, K2, 10);

	printf("state = "); for (i=0; i<18; i++) printf("%02X ", S[i]); printf("\n");

    return 0;
}

// check whether the leftmost bit of the value is 1
unsigned char LMBCheck4Bit(unsigned char val) {
    return ((val & 0x08) >> 3); // returns 1 or 0
}


/* perform multiplication in GF(2^8)
multiplication of a value by x (i.e., by [02]) can be implemented as
a 1-bit left shift followed by a conditional bitwise XOR with pp (e.g. pp = 0001 1011 {1b})
if the leftmost bit of the original value (prior to the shift) is 1.
*/
unsigned char multp4bit(unsigned char x, unsigned char y, unsigned char pp) {
    unsigned char status;
    unsigned char aVal, sVal, result=0;

    aVal = y; sVal = x;

    while (aVal != 0) {
        if ( (aVal & 1) != 0 )
            result ^= sVal;

        status = LMBCheck4Bit(sVal);
        sVal = sVal << 1;

        if (status == 1)
            sVal ^= pp;

        sVal &= 0x0f;
        aVal = (aVal & 0x0f) >> 1;
    }
    return result;
}


int P144(unsigned char *S) {
	unsigned int r, i, j, k, d = 6;
	unsigned char temp;
	unsigned char state[36]; // 36 4-bit state (144 bits / 18 bytes)

	// round constants
	unsigned char RC[12] = {
		1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10
	};

	unsigned char ICd[4][8] = {
		{ 0, 1, 3, 6, 4, 0, 0, 0 },
		{ 0, 1, 3, 7, 6, 4, 0, 0 },
		{ 0, 1, 2, 5, 3, 6, 4, 0 },
		{ 0, 1, 3, 7,15,14,12, 8 }
	};

	// 4x4 s-box
	unsigned char S4ph[16] = {
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
	    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
	};

    unsigned char A[6][6] = {
    	{ 1,  2,  8,  5,  8,  2},
		{ 2,  5,  1,  2,  6, 12},
		{12,  9, 15,  8,  8, 13},
		{13,  5, 11,  3, 10,  1},
		{ 1, 15, 13, 14, 11,  8},
		{ 8,  2,  3,  3,  2,  8}
    };
    unsigned char y[36];
    unsigned char pp = 0x13; // x^4 + x + 1
    unsigned char col;

    // convert 18-byte state to 36 4-bit state
    for (i=0; i<18; i++) {
    	state[i*2  ] = (S[i] & 0xF0) >> 4;
    	state[i*2+1] = (S[i] & 0x0F);
    }

    // 12 rounds of PHOTON P144 permutation
	for (r = 0; r < 12; ++r) {
		// AddConstants (AC)
		for (i=0; i<d; i++) {
			state[i*d] ^= RC[r] ^ ICd[d-5][i];
		}

		// SubCells (SC)
		for (i = 0; i < d*d; ++i) {
			state[i] = S4ph[state[i]];
		}

		// ShiftRows (ShR)
		// row 0 is unmoved
		// moving row 1 to row d-1
		for (i=1; i<d; i++) {
			// number of rotations
			// row j is rotated j times to the left
			for (j=0; j<i; j++) {
				// col 0 to col d-1
				temp = state[i*d];
				for (k=0; k<(d-1); k++) {
					state[i*d+k] = state[i*d+k+1];
				}
				state[i*d+k] = temp;
			}
		}

		// MixColumnsSerial
		for (i=0; i<d*d; i++) y[i] = 0;

		for (col=0; col<d; col++) {
			for (i=0; i<d; i++) {
				for (j=0; j<d; j++) {
					y[i*d+col] ^= multp4bit(A[i][j], state[j*d+col], pp);
				}
			}
		}

		for (i=0; i<d*d; i++) state[i] = y[i];
	}

	// copy state back to S
	for (i=0; i<18; i++) {
		S[i] =  (state[i*2  ] << 4);
		S[i] ^= state[i*2+1];
	}

	return 0;
}

/*
 * hash module. See Figure 2 of Beetle TCHES paper, with some modification to the parameters
 * the parameter 'l' in the original paper is replaced with numBlocks, which is the number of 8-byte blocks in D
 */
int hash(unsigned char *IV, unsigned char *D, int numBlocks, unsigned char constant, int enc, unsigned char O[][8]) {
	unsigned char Y[8];
	unsigned char Z[10];
	unsigned char XZ[18]; // concatenation of X and Z
	int i;

	printf("\nhash\n---\n");

	// copy the 18-byte state (IV) to XZ
	memcpy(XZ, IV, 18);

	printf("state = "); for (i=0; i<18; i++) printf("%02X ", XZ[i]); printf("\n");

	P144(XZ);

	printf("state (after single f) = "); for (i=0; i<18; i++) printf("%02X ", XZ[i]); printf("\n");

	for (i=1; i<=numBlocks; i++) {
		if (enc==1) {
			// copy the first 8 bytes of XZ to Y
			memcpy(Y, XZ, 8);

			// copy current 8-byte of message to X
			memcpy(O[i], D + ((i-1)*8), 8);

			rho(Y, O[i]);

			// copy output of rho to the first 8 bytes of XZ
			memcpy(XZ, Y, 8);
		}
		else {
			// implement inverse of rho
		}

		if (i==numBlocks) {
			// copy the last 10 bytes of XZ to Z
			memcpy(Z, XZ + 8, 10);

			// XOR the last byte of Z with the constant (is this correct?)
			Z[9] ^= constant;

			// copy back to XZ
			memcpy(XZ + 8, Z, 8);

			P144(XZ);
		}
		else {
			P144(XZ);
		}
	}

	// copy XZ to D
	memcpy(D, XZ, 18);

	printf("state (after completing all f) = "); for (i=0; i<18; i++) printf("%02X ",D[i]); printf("\n");

	return 0;
}

/*
 * Proc-A module. See Figure 2 of Beetle TCHES paper, with some modification to the parameters
 *
 * IV: basically nonce
 * A: associated data bytes
 * numBlocks: number of r-bit blocks of A
 * constant: constA
 * O: output of encryption, for proc_A, this will not be used
 */
int proc_A(unsigned char *IV, unsigned char *A, int numBlocks, unsigned char constant, unsigned char O[][8]) {

	printf("\nproc_A\n---\n");

	hash(IV, A, numBlocks, constant, 1, O);
	return 0;
}

/*
 * Proc-M module. See Figure 2 of Beetle TCHES paper, with some modification to the parameters
 *
 * IV: basically nonce
 * M: message bytes
 * numBlocks: number of r-bit blocks of M
 * constant: constM
 * O: this stores the ciphertext bytes
 */
int proc_M(unsigned char *IV, unsigned char *M, int numBlocks, unsigned char constant, unsigned char O[][8]) {

	printf("\nproc_M\n---\n");

	hash(IV, M, numBlocks, constant, 1, O);
	return 0;
}

/*
 * N: 8-byte nonce
 * A: associated data
 * lenA: length of A in bits
 * M: message
 * lenB: length of M in bits
 * r: rate in bits (64 bits for beetle[light+]
 * K: the key bytes (18 bytes for beetle[light+]
 * C: the ciphertext consists of 8-byte blocks
 */
int beetle_light_encrypt(unsigned char *N, unsigned char *A, int lenA, unsigned char *M, int lenM, int r,
		unsigned char *K, unsigned char C[][8]) {
	unsigned char constA;
	unsigned char constM;
	unsigned char S[18];
	int i;
	int numBlocksA;
	int numBlocksM;
	int bitsBlock, bitsByte;
	int byteIndex;

	// set the state to all-zero
	for (i=0; i<18; i++) S[i] = 0;

	// check whether or not the associated data is in multiple of r bits, or
	// how many bits in the last block? if the answer is zero, then the associated data is already
	// in multiple of r bits
	bitsBlock = lenA % r;

	// get the number of blocks of A
	numBlocksA = lenA/r;
	// if the data is not in multiples or r bits, increment number of blocks counter
	if (bitsBlock > 0) {
		numBlocksA++;
	}

	if (bitsBlock > 0) {
		// A is not in multiple of r bits (it is not a complete block)

		constA = 1;

		// what is the byte index where we will start the pad?
		byteIndex = (lenA / 8);

		// if we divide the above in the usual way, and obtain an even number, then the index is the next byte
		// how many bits in the last byte?
		bitsByte = lenA % 8;

		// if bitsByte equals zero, then we need to pad the next byte
		// macam tak perlu je
		//if (bitsByte == 0) {
		//	byteIndex++;
		//}

		// pad the affected byte
		// if bitsByte <= 6, then we can pad with 10 and as many zeros as required
		if (bitsByte <= 6) {
			A[byteIndex] ^= (0x80 >> bitsByte);
		}
		else {
			// if bitsByte == 7, then pad with bit '1'
			A[byteIndex] ^= 1;

			if (bitsBlock == 63) {
				// then we need to add a new block of all zeros
				// NOT YET IMPLEMENTED
			}
		}

		// pad the rest with zero bytes
		for (i=byteIndex+1; i<(numBlocksA*8); i++) {
			A[i] = 0;
		}
	}
	else {
		// A is a multiple or r bits
		constA = 2;
	}

	// check whether or not the associated data is in multiple of r bits, or
	// how many bits in the last block? if the answer is zero, then the associated data is already
	// in multiple of r bits
	bitsBlock = lenM % r;

	// get the number of blocks of M
	numBlocksM = lenM/r;
	// if the data is not in multiples or r bits, increment number of blocks counter
	if (bitsBlock > 0) {
		numBlocksM++;
	}

	if (bitsBlock > 0) {
		// M is not in multiple of r bits (it is not a complete block)
		constM = 3;

		// what is the byte index where we will start the pad?
		byteIndex = (lenM / 8);

		// if we divide the above in the usual way, and obtain an even number, then the index is the next byte
		// how many bits in the last byte?
		bitsByte = lenM % 8;

		// if bitsByte equals zero, then we need to pad the next byte
		if (bitsByte == 0) {
			byteIndex++;
		}

		// pad the affected byte
		// if bitsByte <= 6, then we can pad with 10 and as many zeros as required
		if (bitsByte <= 6) {
			M[byteIndex] ^= (0x80 >> bitsByte);
		}
		else {
			// if bitsByte == 7, then pad with bit '1'
			M[byteIndex] ^= 1;

			if (bitsBlock == 63) {
				// then we need to add a new block of all zeros
				// NOT YET IMPLEMENTED
			}
		}

		// pad the rest with zero bytes
		for (i=byteIndex+1; i<(numBlocksM*8); i++) {
			M[i] = 0;
		}
	}
	else {
		constM = 4;
	}

	printf("Nonce           = "); for (i=0; i<8; i++) printf("%02X ", N[i]); printf("\n");
	printf("Key             = "); for (i=0; i<18; i++) printf("%02X ", K[i]); printf("\n");
	printf("Associated Data = "); for (i=0; i<numBlocksA*8; i++) printf("%02X ", A[i]); printf("\n");
	printf("Message         = "); for (i=0; i<numBlocksM*8; i++) printf("%02X ", M[i]); printf("\n");

	beetle_light_init(S, N, K);
	proc_A(S, A, numBlocksA, constA, C);
	proc_M(S, M, numBlocksM, constM, C);

	return 0;
}

int main() {
	//unsigned char X[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	//unsigned char Y[8] = { 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	unsigned char K[18] = { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, };
	unsigned char A[4] = { 0x45, 0xf1, 0x81, 0xde };
	unsigned char M[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
							0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
	unsigned char N[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char C[2][8];
	int i, j;
	int lenA = 32;
	int lenM = 128;
	int numBlockM = lenM/64;

	beetle_light_encrypt(N, A, 32, M, 128, 64, K, C);
	//shuffle(X);
	//printf("%02X %02X %02X %02X\n", X[0], X[1], X[2], X[3]);
	//printf("%02X %02X %02X %02X\n", X[4], X[5], X[6], X[7]);

	//rho(X, Y);
	printf("ciphertext = "); for (i=0; i<numBlockM; i++) for (j=0; j<8; j++) printf("%02X ",C[i][j]); printf("\n");

	return 0;
}
