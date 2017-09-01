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
#include <algorithm>

#define TWO_P_32 4294967296

#define BUFFER_SIZE 128

#define NUM_CALCS 4
#define NUM_INTER_RES 2


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


typedef struct DistinguisherResult {
	__m128i expKey[6];
	uint8_t con[16];
	uint64_t collisions;
} DistinguisherResult;


void aesFun(DistinguisherResult* set, uint8_t* res);

void printm128i(__m128i p);


void printm128i(__m128i p)
{
	__m128i* t = (__m128i *)aligned_malloc(128, 1);
	_mm_store_si128(t, p);
	unsigned char* c = (unsigned char*)t;

	for (auto i = 0; i < 16; i++)
	{
		std::cout << std::hex << (int)c[i] << " ";
		if (i > 0 && (i+1) % 4 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;

}

void printBytes(uint8_t b[16])
{
	for (auto i = 0; i < 16; i++)
	{
		std::cout << std::hex << (int)b[i] << " ";
		if (i > 0 && (i+1) % 4 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;
}


void aesFun(DistinguisherResult* set, uint8_t* res)
{

	srand((unsigned int)time(NULL));
	
	// generate random key
	uint8_t key[16];
	for (int i = 0; i < 16; i++)
		key[i] = rand();

	// generate random const
	for (int i = 0; i < 16; i++)
		set->con[i] = rand();

	__m128i key128 = _mm_setr_epi8(key[15], key[14], key[13], key[12], key[11], key[10], key[9], key[8], key[7], key[6], key[5], key[4], key[3], key[2], key[1], key[0]);
		
	set->expKey[0] = _mm_load_si128((__m128i*)(&key128));
	set->expKey[1] = KEYEXP(set->expKey[0], 0x01);
	set->expKey[2] = KEYEXP(set->expKey[1], 0x02);
	set->expKey[3] = KEYEXP(set->expKey[2], 0x04);
	set->expKey[4] = KEYEXP(set->expKey[3], 0x08);
	set->expKey[5] = KEYEXP(set->expKey[4], 0x10);
	
	uint8_t v0  = 0;
	uint8_t v5  = 0;
	uint8_t v10 = 0;
	uint8_t v15 = 0;
	__m128i mes128;
	__m128i* resMem = (__m128i *)aligned_malloc(128, 16);
	uint32_t* buffer = (uint32_t*)calloc(BUFFER_SIZE, sizeof(uint32_t));
	int elemensInBuffer = 0;
	//for (uint64_t i = 0; i < 321;)
	for (uint64_t i = 0; i < TWO_P_32;)
	{

		// build plaintext
		v0  = (uint8_t)(i >> 24); // msb
		v5  = (uint8_t)(i >> 16);
		v10 = (uint8_t)(i >> 8);
		v15 = (uint8_t)(i >> 0); // lsb

								 //                       lsb						                                       msb
								 //                       15   14   13   12   11   10   9   8   7   6   5   4   3   2   1   0
								 //mes128 = _mm_setr_epi8(c15, c14, c13, c12, c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0);
		mes128 = _mm_setr_epi8(v15, set->con[14], set->con[13], set->con[12], set->con[11], v10, set->con[9], set->con[8], set->con[7], set->con[6], v5, set->con[4], set->con[3], set->con[2], set->con[1], v0);

		// do 5 rounds aes
		// load the 16 bytes message into m 
		__m128i m = _mm_load_si128((const __m128i *) &mes128);
		// first xor the loaded message with k0, which is the AES key supplied /
		m = _mm_xor_si128(m, set->expKey[0]);
		// then do 5 rounds of aesenc, using the associated key parts /
		m = _mm_aesenc_si128(m, set->expKey[1]);
		m = _mm_aesenc_si128(m, set->expKey[2]);
		m = _mm_aesenc_si128(m, set->expKey[3]);
		m = _mm_aesenc_si128(m, set->expKey[4]);
		m = _mm_aesenclast_si128(m, set->expKey[5]);
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

		buffer[elemensInBuffer] = diag;
		elemensInBuffer++;

		if ((elemensInBuffer == 32) || (i == (TWO_P_32-1)))
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

	uint64_t pairs = 0;
	uint64_t tmp = 0;
	for (uint64_t i = 0; i <= TWO_P_32; ++i)
	{
		tmp = 0;
		if (res[i] > 1)
			tmp = (res[i] * (res[i] - 1)) / 2;
		pairs += tmp;
	}
	if (pairs % 8 != 0)
	{
		std::cerr << "###############################################################################" << std::endl;
		std::cerr << "Number of collisions reached unexpected value." << pairs << " is not a multiple of 8." << std::endl  << "Results will be invalid." << std::endl;
		std::cerr << "###############################################################################" << std::endl;
	}

	set->collisions = pairs;

}

int main(int argc, char* argv[])
{
	auto begin = std::chrono::high_resolution_clock::now();


	std::cout << "Doing " << NUM_CALCS << " calculations." << std::endl;
	std::cout << "Reporting intermediary results every " << NUM_INTER_RES << " caculations." << std::endl;

	DistinguisherResult** results = (DistinguisherResult**)calloc(NUM_CALCS, sizeof(DistinguisherResult*));
	
	uint8_t* res = (uint8_t*)calloc(TWO_P_32, sizeof(uint8_t));
	if (res == NULL)
	{
		std::cerr << "Critical Error: Received not enough memory." << std::endl;
		return 0;
	}

	for (uint64_t i = 0; i < NUM_CALCS; i++)
	{
		DistinguisherResult* t = new DistinguisherResult();
		std::thread t1(aesFun, t, res);
		t1.join();
		results[i] = t;
		
		if ((i+1) % NUM_INTER_RES == 0)
		{
			std::cout << "## Intermediary Results: ##" << std::endl;

			for (uint64_t j = 0; j <= i; j++)
			{
				std::cout << "Key: " << std::endl;
				printm128i(results[j]->expKey[0]);

				std::cout << "Constant: " << std::endl;
				printBytes(results[j]->con);


				std::cout << "Collisions: " << results[j]->collisions << std::endl;
			}
			std::cout << "#############" << std::endl << std::endl << std::endl;
		}
		memset(res, 0, TWO_P_32 * sizeof(uint8_t));
		auto tT = std::chrono::high_resolution_clock::now();
		std::cout << "Finished calculation #" << i << " after " << std::chrono::duration_cast<std::chrono::minutes>(tT - begin).count() << " minutes."<< std::endl;
	}

	auto end = std::chrono::high_resolution_clock::now();
	std::cout << "Done after " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes" << std::endl;


	return 0;

	/*
	srand((unsigned int)time(NULL));
	// generate random key
	uint8_t key[16];
	for (int i = 0; i < 16; i++)
		key[i] = rand();

	// generate random const
	uint8_t con[16];
	for (int i = 0; i < 16; i++)
		con[i] = rand();
	*/
	//con[0] = rand();
	//con[1] = rand();
	//con[2] = rand();
	//con[3] = rand();
	//con[4] = rand();
	//con[5] = rand();
	//con[6] = rand();
	//con[7] = rand();
	//con[8] = rand();
	//con[9] = rand();
	//con[10] = rand();
	//con[11] = rand();
	//con[12] = rand();
	//con[13] = rand();
	//con[14] = rand();
	//con[15] = rand();

	//key[ 0] = rand();
	//key[ 1] = rand();
	//key[ 2] = rand();
	//key[ 3] = rand();
	//key[ 4] = rand();
	//key[ 5] = rand();
	//key[ 6] = rand();
	//key[ 7] = rand();
	//key[ 8] = rand();
	//key[ 9] = rand();
	//key[10] = rand();
	//key[11] = rand();
	//key[12] = rand();
	//key[13] = rand();
	//key[14] = rand();
	//key[15] = rand();
	//                             lsb                                                               msb
	//                             15   14   13   12   11   10   9   8   7   6   5   4   3   2   1   0
	//__m128i key128 = _mm_setr_epi8(key[15], key[14], key[13], key[12], key[11], key[10], key[9], key[8], key[7], key[6], key[5], key[4], key[3], key[2], key[1], key[0]);
	//__m128i key128 = _mm_setr_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);


	//__m128i expKey[11];
	//expKey[0] =  _mm_load_si128((__m128i*)(&key128));
	//expKey[1] =  KEYEXP(expKey[0], 0x01);
	//expKey[2] =  KEYEXP(expKey[1], 0x02);
	//expKey[3] =  KEYEXP(expKey[2], 0x04);
	//expKey[4] =  KEYEXP(expKey[3], 0x08);
	//expKey[5] =  KEYEXP(expKey[4], 0x10);
	//expKey[6] =  KEYEXP(expKey[5], 0x20);
	//expKey[7] =  KEYEXP(expKey[6], 0x40);
	//expKey[8] =  KEYEXP(expKey[7], 0x80);
	//expKey[9] =  KEYEXP(expKey[8], 0x1B);
	//expKey[10] = KEYEXP(expKey[9], 0x36);
	//
	////volatile uint64_t sz = (uint64_t)1 << 32;
	//uint8_t* res = (uint8_t*)calloc(TWO_P_32, sizeof(uint8_t));
		
	//volatile uint64_t startNum = 0;
	//volatile uint64_t stopNum = 1;
	//stopNum = stopNum << 32;
	//std::cout << "StopNum: " << stopNum << std::endl;
	//std::cout << "Sz:      "      << sz << std::endl;

	//__m128i mes128;

	

	//auto begin = std::chrono::high_resolution_clock::now();
	//
	//std::thread t1(aesFun, expKey, con);
	//t1.join();
	//
	//auto end = std::chrono::high_resolution_clock::now();
	//std::cout << "Finished main work in " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes." << std::endl;
	//
	//auto begin3 = std::chrono::high_resolution_clock::now();
	//
	//
	//uint64_t remainder = pairs % 8;
	//auto end3 = std::chrono::high_resolution_clock::now();
	//std::cout << "Detected " << pairs << " pairs in " << std::chrono::duration_cast<std::chrono::seconds>(end3 - begin3).count() << " seconds" << std::endl;
	//
	//if (remainder == 0)
	//	std::cout << pairs << " is a multiple of 8 :)" << std::endl;
	//else
	//	std::cout << pairs << " is NOT a multiple of 8 :(" << std::endl;
	//
	//
	////cleanup
	//delete[] res;

	//return 0;

}
#endif