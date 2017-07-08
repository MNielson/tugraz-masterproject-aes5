#ifndef __AES_NI_H__
#define __AES_NI_H__




#include "../Header/aesmain.h"
#include <stdio.h>
#include <wmmintrin.h>
#include <thread>
#include <mutex>
#include <vector>
#include <math.h>

#define KEYEXP(K, I) aes128_keyexpand(K, _mm_aeskeygenassist_si128(K, I))
__m128i aes128_keyexpand(__m128i key, __m128i keygened)
{
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	return _mm_xor_si128(key, keygened);
}

void printM128i(__m128i* p)
{
	for (uint8_t i = 1; i <= 16; i++)
	{
		printf("%X ", p->m128i_u8[i - 1]);
		if (i % 4 == 0 && i > 0)
			printf("\n");
	}	
	return;
}


void thrAes5(const uint32_t &threadNum, const uint32_t &numThreads, __m128i expKey[], uint8_t res[]);

static std::mutex mtx;


void main()
{
	AesMain aesMain;
	uint8_t key[16] = { 0 };
	uint8_t data[16] = { 0 };
	uint8_t expandedKey[176];
	aesMain.expandKey(expandedKey, 176, key, 16);

	printf("Key: \n");
	aesMain.printBlock(key, 16);
	printf("\nData In: \n");
	aesMain.printBlock(data, 16);
	aesMain.aesWithoutKeyExpansion(data, expandedKey, 10, false);
	printf("\nData Out: \n");
	aesMain.printBlock(data, 16);


	__m128i key128;
	key128.m128i_u64[1] = 0x0000000000000000;
	key128.m128i_u64[0] = 0x0000000000000000;

	__m128i expKey[11];
	expKey[0]  = _mm_load_si128((__m128i*)(&key128));
	expKey[1]  = KEYEXP(expKey[0], 0x01);
	expKey[2]  = KEYEXP(expKey[1], 0x02);
	expKey[3]  = KEYEXP(expKey[2], 0x04);
	expKey[4]  = KEYEXP(expKey[3], 0x08);
	expKey[5]  = KEYEXP(expKey[4], 0x10);
	expKey[6]  = KEYEXP(expKey[5], 0x20);
	expKey[7]  = KEYEXP(expKey[6], 0x40);
	expKey[8]  = KEYEXP(expKey[7], 0x80);
	expKey[9]  = KEYEXP(expKey[8], 0x1B);
	expKey[10] = KEYEXP(expKey[9], 0x36);

	uint32_t numThreads =8;
	std::vector<std::thread> threads;
	uint64_t sz = (uint64_t)1 << 32;
	uint8_t* res = new uint8_t[sz+1]();

	//start worker threads
	for (uint32_t threadNum = 0; threadNum < numThreads; ++threadNum)
	{
		threads.push_back( std::thread(thrAes5, std::ref(threadNum), std::ref(numThreads), std::ref(expKey), std::ref(res)) );
	}
	// wait for worker threads to finish
	for (auto &t : threads)
	{
		t.join();
	}

	// do something with res

	//cleanup
	delete[] res;


}


void thrAes5(const uint32_t &threadNum, const uint32_t &numThreads, __m128i expKey[], uint8_t res[])
{
	uint32_t startNum = 0;
	uint32_t stopNum  = 0;
	uint32_t stepSize = 0;
	uint64_t sz = (uint64_t)1 << 32;

#ifdef _DEBUG
	stepSize = 100;
#else
	stepSize = (uint32_t)floor(sz / (uint64_t)numThreads);
#endif
	
	if (threadNum == 0)
	{
		startNum = 0;
		stopNum = stepSize;
	}
	else if (threadNum == numThreads)
	{
		startNum = threadNum * stepSize + 1;
		stopNum = UINT32_MAX;
	}
	else
	{
		startNum = threadNum * stepSize + 1;
		stopNum = startNum + stepSize - 1;
	}
	

	__m128i mes128;
	__m128i out;

	for (uint32_t i = startNum; i <= stopNum; ++i)
	{
		
		// build plaintext
		mes128.m128i_u64[1] = 0x0000000000000000;
		mes128.m128i_u64[0] = 0x0000000000000000;

		mes128.m128i_u8[0]  = (uint8_t)(i >> 24); // msb
		mes128.m128i_u8[5]  = (uint8_t)(i >> 16);
		mes128.m128i_u8[9]  = (uint8_t)(i >>  8);
		mes128.m128i_u8[15] = (uint8_t)(i >>  0); // lsb

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
		m = _mm_aesenc_si128(m, expKey[5]);
		// and then we store the result in an out variable /
		_mm_store_si128((__m128i *) &out, m);


		// restore diagonal val

		uint32_t diag = uint32_t((out.m128i_u8[0])  << 24 |
			                     (out.m128i_u8[5])  << 16 |
			                     (out.m128i_u8[9])  <<  8 |
			                     (out.m128i_u8[15]) <<  0);

		
		mtx.lock();
		res[i] = res[i] + 1;
		mtx.unlock();
	}

}

#endif