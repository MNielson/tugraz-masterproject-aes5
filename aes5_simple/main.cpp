#ifndef __AES_NI_H__
#define __AES_NI_H__


#include <stdio.h>
#include <iostream>
#include <string>
#include <wmmintrin.h>
#include <thread>
#include <vector>
#include <math.h>
#include <iostream>
#include <sstream>
#include <random>
#include <cstdint>

#define TWO_P_32 4294967296
#define BUFFER_SIZE 64
#define SAMPLES 4
#define INTER_RES 2


#define KEYEXP(K, I) aes128_keyexpand(K, _mm_aeskeygenassist_si128(K, I))
__m128i aes128_keyexpand(__m128i key, __m128i keygened)
{
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	return _mm_xor_si128(key, keygened);
}

inline void* aligned_malloc(size_t size, size_t align) {
	void *result;
#ifdef _MSC_VER 
	result = _aligned_malloc(size, align);
#else 
	if (posix_memalign(&result, align, size)) result = 0;
#endif
	return result;
}

typedef struct {
	uint8_t con[16];
	uint8_t key[16];
	uint64_t collisions;
} Sample;


uint64_t aesDistinguisher(uint8_t* res, __m128i key, uint8_t* con)
{
	uint8_t v0 = 0;
	uint8_t v5 = 0;
	uint8_t v10 = 0;
	uint8_t v15 = 0;
	__m128i mes128;
	__m128i* resMem = (__m128i *)aligned_malloc(128, 16);

	__m128i expKey[6];
	expKey[0] = _mm_load_si128((__m128i*)(&key));
	expKey[1] = KEYEXP(expKey[0], 0x01);
	expKey[2] = KEYEXP(expKey[1], 0x02);
	expKey[3] = KEYEXP(expKey[2], 0x04);
	expKey[4] = KEYEXP(expKey[3], 0x08);
	expKey[5] = KEYEXP(expKey[4], 0x10);

	uint32_t* buffer = (uint32_t*)calloc(BUFFER_SIZE, sizeof(uint32_t));
	int elemensInBuffer = 0;
	
	for (uint64_t i = 0; i < TWO_P_32;)
	{
		// build plaintext
		v0 = (uint8_t)(i >> 24); // msb
		v5 = (uint8_t)(i >> 16);
		v10 = (uint8_t)(i >> 8);
		v15 = (uint8_t)(i >> 0); // lsb

		mes128 = _mm_setr_epi8(v15, con[14], con[13], con[12], con[11], v10, con[9], con[8], con[7], con[6], v5, con[4], con[3], con[2], con[1], v0);

		// do 5 rounds aes
		// load the 16 bytes message into m 
		__m128i m = _mm_load_si128((const __m128i *) &mes128);
		// first xor the loaded message with k0, which is the AES key supplied /
		m = _mm_xor_si128(m, expKey[0]);
		// then do 5 rounds of aesenc, using the associated key parts /
		m = _mm_aesenc_si128(m, expKey[1]);
		m = _mm_aesenc_si128(m, expKey[2]);
		m = _mm_aesenc_si128(m, expKey[3]);
		m = _mm_aesenc_si128(m, expKey[4]);
		m = _mm_aesenclast_si128(m, expKey[5]);
		// and then we store the result in an out variable /
		_mm_store_si128(resMem, m);

		// restore diagonal val
		unsigned char* foo = (unsigned char*)resMem;
		uint32_t x1 = foo[0];
		uint32_t x2 = foo[13];
		uint32_t x3 = foo[10];
		uint32_t x4 = foo[7];

		x1 = x1 << 0;
		x2 = x2 << 8;
		x3 = x3 << 16;
		x4 = x4 << 24;

		volatile uint32_t diag = (x1 | x2 | x3 | x4);
		//res[diag] = res[diag] + 1;

		buffer[elemensInBuffer] = diag;
		
		elemensInBuffer++;
		
		if (elemensInBuffer == BUFFER_SIZE)
		{
			for (int j = 0; j < elemensInBuffer; j++)
			{
				uint32_t t = buffer[j];
				res[t] = res[t] + 1;
			}
			elemensInBuffer = 0;
			}
		i = i + 1;
	}

	uint64_t collisions = 0;
	uint64_t tmp = 0;
	for (uint64_t i = 0; i <= TWO_P_32; ++i)
	{
		tmp = 0;
		if (res[i] > 1)
			tmp = (res[i] * (res[i] - 1)) / 2;
		collisions += tmp;
	}

	if (collisions % 8)
		std::cerr << "Error: " << collisions << "is not a multiple of 8." << std::endl;

	return collisions;
}

int main(int argc, char* argv[])
{
	uint8_t* res = (uint8_t*)calloc(TWO_P_32, sizeof(uint8_t));
	
	Sample* s1 = new Sample;
	
	memset(res, 0, TWO_P_32 * sizeof(uint8_t));

	srand((unsigned int)time(NULL));
	// generate random key

	for (int i = 0; i < 16; ++i)
		s1->key[i] = rand();
	__m128i key128 = _mm_setr_epi8(s1->key[15], s1->key[14], s1->key[13], s1->key[12], s1->key[11], s1->key[10], s1->key[9], s1->key[8], s1->key[7], s1->key[6], s1->key[5], s1->key[4], s1->key[3], s1->key[2], s1->key[1], s1->key[0]);

	// generate random const
	for (int i = 0; i < 16; ++i)
		s1->con[i] = rand();

	auto begin = std::chrono::high_resolution_clock::now();
	
	s1->collisions = aesDistinguisher(res, key128, s1->con);
	
	auto end = std::chrono::high_resolution_clock::now();
	std::cout << "Finished main work in " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes." << std::endl;
	if (s1->collisions % 8 == 0)
		std::cout << ":)" << std::endl;

	//cleanup
	delete[] res;
	return 0;
}

#endif