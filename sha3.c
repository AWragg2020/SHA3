#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

unsigned long concatenate(unsigned char **Z, const unsigned char *X,
		unsigned long X_len, const unsigned char *Y,
		unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
		unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);
unsigned char rc(unsigned int t);

//Pre-declaration of function keccak_p
unsigned char *keccak_p(unsigned char *S, unsigned int b, unsigned int nr);

//The library math.h was not working properly in the local machine, so I defined this particular function
unsigned int pow(unsigned int a, unsigned int b);

//Type definition of a State Array, because it's easier to work with this than pointers
//Each of its elements holds a 64 bit word
typedef struct StateArray{
	uint64_t array[5][5];
} StateArray;

//Declaration of Rnd function
StateArray Rnd(StateArray A, unsigned int ir);
//Special functions
StateArray iota(StateArray A, unsigned int ir);
StateArray xi(StateArray A);
StateArray pi(StateArray A);
StateArray ro(StateArray A);
StateArray theta(StateArray A);

/*
 *Declaration of the global variables offsets and RC:
 *Both provided in the file KeccakF-1600-IntermediateValues.txt
 */
int offsets[5][5]={{0,36,3,41,18},{1,44,10,45,2},{62,6,43,15,61},{28,55,25,21,56},{27,20,39,8,14}};
uint64_t RC[24] = {
		0x0000000000000001,
		0x0000000000008082,
		0x800000000000808A,
		0x8000000080008000,
		0x000000000000808B,
		0x0000000080000001,
		0x8000000080008081,
		0x8000000000008009,
		0x000000000000008A,
		0x0000000000000088,
		0x0000000080008009,
		0x000000008000000A,
		0x000000008000808B,
		0x800000000000008B,
		0x8000000000008089,
		0x8000000000008003,
		0x8000000000008002,
		0x8000000000000080,
		0x000000000000800A,
		0x800000008000000A,
		0x8000000080008081,
		0x8000000000008080,
		0x0000000080000001,
		0x8000000080008008
};


/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
		unsigned int l)
{
	/* The hash size must be one of the supported ones */
	if (s != 224 && s != 256 && s != 384 && s != 512)
		return;

	/* Implement the rest of this function */

	//Concatenate 01 to the original message
	unsigned char *N=NULL;
	unsigned long N_length_bits;
	N_length_bits=concatenate_01(&N,m,l);

	//First, some variable definitions
	unsigned int b,c,r;
	b=1600;
	c=512;
	r=b-c;

	//Sponge algorithm
	//1. P = N || pad(r, len(N))
	unsigned char *padding=NULL;
	unsigned long padding_len_bits;
	padding_len_bits=pad10x1(&padding,r,N_length_bits);

	unsigned char *P=NULL;
	unsigned long P_len_bits;
	P_len_bits=concatenate(&P,N,N_length_bits,padding,padding_len_bits);

	//2. n = len(P) / r
	unsigned long n = P_len_bits/r;

	//3. c = b-r <- Already done

	//4. P0, ..., Pn-1 -> P = P0 || ... || Pn-1
	unsigned char *Pi[n];
	unsigned int i,j;
	for(i=0; i<n; i++){
		Pi[i]=calloc(r+1,sizeof(unsigned char));
		for(j=0; j<r/8; j++){
			Pi[i][j]=P[i*(r/8)+j];
		}
	}

	//5. S = 0^b
	unsigned char *S=calloc(b/8,sizeof(unsigned char));

	//6. Kecccak-p[1600,24](S)
	unsigned char *zeroes=calloc(c/8,sizeof(unsigned char));
	unsigned char *Pi_conc_zeroes=calloc(b/8,sizeof(unsigned char));
	unsigned char *S_xor=calloc(b/8,sizeof(unsigned char));
	unsigned int index2;
	//printf("%d",n);
	for(i=0; i<n; i++){
		//Here we obtain Pi || 0^c
		concatenate(&Pi_conc_zeroes,Pi[i],r,zeroes,c);

		// S xor (Pi || 0^c)
		for(index2=0; index2<b/8; index2++){
			S_xor[index2]=S[index2]^Pi_conc_zeroes[index2];
		}
		//Apply keccak-p function
		S=keccak_p(S_xor, 1600, 24);
	}

	//7. 8. 9. can really be compressed in a single action due to the fact that the input
	//is always going to be bigger than the fixed output length
	memcpy(d,S,s/8);
}

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
		unsigned long X_len, const unsigned char *Y,
		unsigned long Y_len)
{
	/* The bit length of Z: the sum of X_len and Y_len */
	unsigned long Z_bit_len = X_len + Y_len;
	/* The byte length of Z:
	 * the least multiple of 8 greater than X_len + Y_len */
	unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
	// Allocate the output string and initialize it to 0
	*Z = calloc(Z_byte_len, sizeof(unsigned char));
	if (*Z == NULL)
		return 0;
	// Copy X_len/8 bytes from X to Z
	memcpy(*Z, X, X_len / 8);
	// Copy X_len%8 bits from X to Z
	for (unsigned int i = 0; i < X_len % 8; i++) {
		(*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
	}
	// Copy Y_len bits from Y to Z
	unsigned long Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
	unsigned long Y_byte_cursor = 0, Y_bit_cursor = 0;
	unsigned int v;
	for (unsigned long i = 0; i < Y_len; i++) {
		// Get the bit
		v = ((Y[Y_byte_cursor] >> Y_bit_cursor) & 1);
		// Set the bit
		(*Z)[Z_byte_cursor] |= (v << Z_bit_cursor);
		// Increment cursors
		if (++Y_bit_cursor == 8) {
			Y_byte_cursor++;
			Y_bit_cursor = 0;
		}
		if (++Z_bit_cursor == 8) {
			Z_byte_cursor++;
			Z_bit_cursor = 0;
		}
	}
	return Z_bit_len;
}

/* Concatenate the 01 bit string to a given bit string (X||01)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
		unsigned long X_len)
{
	/* Due to the SHA-3 bit string representation convention, the 01
	 * bit string is represented in hexadecimal as 0x02.
	 * See Appendix B.1 of the Standard.
	 */
	unsigned char zeroone[] = { 0x02 };
	return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
	/* 1. j = (-m-2) mod x */
	long j = x - ((m + 2) % x);
	/* 2. P = 1 || zeroes(j) || 1 */
	// Compute P bit and byte length
	unsigned long P_bit_len = 2 + j;
	unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
	// Allocate P and initialize to 0
	*P = calloc(P_byte_len, sizeof(unsigned char));
	if (*P == NULL)
		return 0;
	// Set the 1st bit of P to 1
	(*P)[0] |= 1;
	// Set the last bit of P to 1
	(*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

	return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
	unsigned int tmod = t % 255;
	/* 1. If t mod255 = 0, return 1 */
	if (tmod == 0)
		return 1;
	/* 2. Let R = 10000000
	 *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
	unsigned char R = 0x80, R0;
	/* 3. For i from 1 to t mod 255 */
	for (unsigned int i = 1; i <= tmod; i++) {
		/* a. R = 0 || R */
		R0 = 0;
		/* b. R[0] ^= R[8] */
		R0 ^= (R & 1);
		/* c. R[4] ^= R[8] */
		R ^= (R & 0x1) << 4;
		/* d. R[5] ^= R[8] */
		R ^= (R & 0x1) << 3;
		/* e. R[6] ^= R[8] */
		R ^= (R & 0x1) << 2;
		/* Shift right by one */
		R >>= 1;
		/* Copy the value of R0 in */
		R ^= R0 << 7;
	}
	/* 4. Return R[0] */
	return R >> 7;
}

//This function was not really neccesary in terms of efficency because it's already implemented in the c
//language. However, due to some unexpected errors with the library math.h, I refered to implent it again myself
/*
 * Return a^b
 * a - input base
 * b - input exponent
 */
unsigned int pow(unsigned int a, unsigned int b){
	unsigned int r=1, i;
	for(i=0; i<b; i++){
		r*=a;
	}
	return r;
}

/*
 * Function keccak-p
 *
 * *S - Input string
 * b - Lenght of input string
 * nr - Number of rounds
 */
unsigned char *keccak_p(unsigned char *S, unsigned int b, unsigned int nr){

	uint64_t *state=(uint64_t *)S;

	//1. Convert S into state array A
	StateArray A;
	int x, y, l;
	l=6;
	for(x=0; x<5; x++){
		for(y=0; y<5; y++){
			A.array[x][y]=state[5*y+x];
		}
	}

	//2. For ir from 12+2l-nr to 12+2l-1, let A=Rnd(A, ir)
	int ir;
	for(ir=12+2*l-nr; ir<24; ir++){
		A=Rnd(A, ir);
	}

	//3. Convert A into S' of length 1600
	//First I do allocate a string of length b/8 because that's what is going to be returned
	//and a uint64_t of the same length because ethat's what I'm going to work with
	unsigned char *S2=calloc(b/8,sizeof(unsigned char));
	uint64_t *state2=calloc(b/8,sizeof(unsigned char));

	//Returning the state array t a regular string according to specification
	for(x=0; x<5; x++){
		for(y=0; y<5; y++){
			state2[5*y+x]=A.array[x][y];
		}
	}

	//This way, I assign S2, the return value, the value of the string obtained from the state array
	S2=(unsigned char  *)state2;

	//4. Return S'
	return S2;

}

StateArray Rnd(StateArray A, unsigned int ir){
	return iota(xi(pi(ro(theta(A)))),ir);
}

StateArray iota(StateArray A, unsigned int ir){
	//1. For all triplets (x,y,z), let A'[x,y,z] = A[x,y,z]
	StateArray A2;
	int x,y;
	for(x=0; x<5; x++){
		for(y=0; y<5; y++){
			A2.array[x][y]=A.array[x][y];
		}
	}

	//2. Let RC=0^w
	//Not required since RC is already defined

	//3. For j from 0 to l, let RC[(2^j)-1]=rc(j+7*ir)
	//Unnecessary since all RC values are already defined as a global variable

	//4. For all z, let A'[0,0,z]=A'[0,0,z] xor RC[z]
	//Done this way because of the declaration of RC
	A2.array[0][0]^=RC[ir];

	//5. Return A'
	return A2;
}

StateArray xi(StateArray A){
	//1. For all triples (x,y,z) let A'[x,y,z]=A[x,y,z] xor ((A[(x+1) mod 5, y,z] xor 1) & A[(x+2) mode 5, y,z])
	//Obtaining the 64 bits with 1
	uint64_t one=0;
	one=~one;
	//Rest of the algorithm, self explanatory
	StateArray A2;
	int x,y;
	for(x=0; x<5;x++){
		for(y=0; y<5; y++){
			A2.array[x][y]=A.array[x][y]^((A.array[(x+1)%5][y]^one)&A.array[(x+2)%5][y]);
		}
	}

	//2. Retrurn A'
	return A2;
}

StateArray pi(StateArray A){
	//1. For all triplets (x,y,z), let A'[x,y,z]=A[(x+3y)mod5,x,z]
	StateArray A2;
	int x,y;
	for(x=0; x<5; x++){
		for(y=0; y<5; y++){
			A2.array[x][y]=A.array[(x+3*y)%5][x];
		}
	}

	//2. Return A'
	return A2;
}

StateArray ro(StateArray A){
	//1. For all z let A'[0,0,z]=A[0,0,z]
	StateArray A2;
	A2.array[0][0]=A.array[0][0];

	int x=1,y=0,aux,i;
	for(i=0; i<24; i++){
		A2.array[x][y]=ROL64(A.array[x][y],offsets[x][y]);
		//aux variable needed due to swapping values
		aux=x;
		x=y;
		y=(2*aux+3*y)%5;
	}

	//4. Return A'
	return A2;
}

StateArray theta(StateArray A){
	StateArray A2;
	//1. For all pairs (x,z) let C[x,z]=A[x,0,z] xor A[x,1,z] xor A[x,2,z] xor A[x,3,z] xor A[x,4,z]
	uint64_t C[5];
	int x,y;
	for(x=0; x<5; x++){
		C[x]=A.array[x][0]^A.array[x][1]^A.array[x][2]^A.array[x][3]^A.array[x][4];
	}

	//2. For all pairs (x,z) let D[x,z]=C[(x-1)mod 5,z] xor C[(x+1)mod 5,(z-1)mod w]
	uint64_t D[5];
	for(x=0; x<5; x++){
		//This one requires some explanation. The fact that I chose to call to C[(x+4)%5] instead of C[(x-1)%5]
				//is because x starts from 0, thus giving C[-1] in the first iteration, making no sense at all
		D[x]=C[(x+4)%5]^ROL64(C[(x+1)%5],1);
	}

	//3. For all triples (x,y,z) let A'[x,y,z]=A[x,y,z] xor D[x,z]
	for(x=0; x<5; x++){
		for(y=0; y<5; y++){
			A2.array[x][y]=A.array[x][y]^D[x];
		}
	}

	return A2;
}
