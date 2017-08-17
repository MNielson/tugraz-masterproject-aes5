#ifndef __AES_NI_H__
#define __AES_NI_H__




#include <stdio.h>
#include <iostream>
#include <string>
#include <wmmintrin.h>
#include <thread>
#include <mutex>
#include <vector>
#include <math.h>
#include <iostream>
#include <sstream>
#include <cstdint>

enum StepSizeSetting { FULL, PER_THREAD, TOTAL };

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


void thrAes5(const uint64_t startNum, const uint64_t stopNum, __m128i expKey[], uint8_t res[]);
uint64_t workPerThread(const StepSizeSetting setting, const uint64_t numWork, const uint64_t numThreads);
uint64_t totalWork(StepSizeSetting setting, uint64_t workload, uint64_t numThreads);

void printUsage(std::string name);
StepSizeSetting parseSetting(std::string setting);

static std::mutex mtx;

int main(int argc, char* argv[])
{
	
	StepSizeSetting stepSizeSetting = FULL;
	uint64_t workload = 1;
	uint64_t numThreads = 1;
	if ( (argc == 1 || argc > 4) )
	{
		printUsage(argv[0]);
		return 0;
	}
	else
	{
		stepSizeSetting = parseSetting(argv[1]);
		if (argc >= 3)
		{
			std::istringstream workStr(argv[2]);
			workStr >> workload;
		}
		if (argc == 4)
		{
			std::istringstream threadStr(argv[3]);
			threadStr >> numThreads;
		}
	}


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

	std::vector<std::thread> threads;
	uint64_t sz = (uint64_t)1 << 32;
	uint8_t* res = new uint8_t[sz+1]();

	uint64_t stepSize = workPerThread(stepSizeSetting, workload, numThreads);
	uint64_t totalWorkNum = totalWork(stepSizeSetting, workload, numThreads);
	
	uint64_t startNum = 0;
	uint64_t stopNum = stepSize - 1;
	auto begin = std::chrono::high_resolution_clock::now();
	//start worker threads
	for (uint32_t threadNum = 0; threadNum < numThreads; ++threadNum)
	{		if (threadNum+1 == numThreads && stopNum < totalWorkNum - 1)
		{
			// make sure all remaining work is handed to last thread
			// this can lead to last thread getting significantly more work than others (ex: wl 13, th 5)
			stopNum = totalWorkNum - 1;
		}
		threads.push_back(std::thread(thrAes5, startNum, stopNum, std::ref(expKey), std::ref(res)));
		startNum = stopNum + 1;
		stopNum = startNum + stepSize - 1;		
	}

	// wait for worker threads to finish
	for (auto &t : threads)
	{
		t.join();
	}

	// do something with res
	auto end = std::chrono::high_resolution_clock::now();
	
	std::cout << "Computed "<< totalWorkNum << " instances aes5 with " << numThreads << " threads in " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << " seconds" << std::endl;

	auto begin2 = std::chrono::high_resolution_clock::now();
	uint64_t workDone = 0;
	for (uint64_t i = 0; i <= sz; ++i)
		workDone += res[i];
	auto end2 = std::chrono::high_resolution_clock::now();
	std::cout << "Detected " << workDone << " pieces of work done in " << std::chrono::duration_cast<std::chrono::milliseconds>(end2 - begin2).count() << " milliseconds" << std::endl;



	auto begin3 = std::chrono::high_resolution_clock::now();
	uint64_t pairs = 0;
	uint64_t tmp = 0;
	for (uint64_t i = 0; i <= sz; ++i)
	{
		tmp = 0;
		if (res[i] > 1)
			tmp = (res[i] * (res[i] - 1)) / 2;
		pairs += tmp;
	}
		
	uint64_t remainder = pairs % 8;
	auto end3 = std::chrono::high_resolution_clock::now();
	std::cout << "Detected " << pairs << " pairs in " << std::chrono::duration_cast<std::chrono::milliseconds>(end3 - begin3).count() << " milliseconds" << std::endl;

	if (remainder == 0)
		std::cout << pairs << " is a multiple of 8 :)" << std::endl;
	else
		std::cout << pairs << " is NOT a multiple of 8 :(" << std::endl;
		

	//cleanup
	delete[] res;
	
	return 0;

}

uint64_t workPerThread(const StepSizeSetting setting, const uint64_t numWork, const uint64_t numThreads)
{
	uint64_t stepSize = 0;

	uint64_t maxWork = (uint64_t)1 << 32;

	switch (setting)
	{
	case FULL:
		stepSize = (uint64_t)floor(maxWork / numThreads);
		break;

	case PER_THREAD:
		stepSize = numWork;
		break;

	case TOTAL:
		stepSize = (uint64_t)floor(numWork / numThreads);
		break;
	}
	return stepSize;
}

uint64_t totalWork(StepSizeSetting setting, uint64_t workload, uint64_t numThreads)
{
	uint64_t totalWork = 0;
	switch (setting)
	{
	case FULL:
		totalWork = (uint64_t)1 << 32;
		break;
	case TOTAL:
		totalWork = workload;
		break;
	case PER_THREAD:
		totalWork = workload * numThreads;
		break;
	}
	return totalWork;
}

void thrAes5(const uint64_t startNum, const uint64_t stopNum, __m128i expKey[], uint8_t res[])
{
	__m128i mes128;
	__m128i out;

	for (uint64_t i = startNum; i <= stopNum; i++)
	{
		
		// build plaintext
		mes128.m128i_u64[1] = 0x0000000000000000;
		mes128.m128i_u64[0] = 0x0000000000000000;

		mes128.m128i_u8[0]  = (uint8_t)(i >> 24); // msb
		mes128.m128i_u8[5]  = (uint8_t)(i >> 16);
		mes128.m128i_u8[10] = (uint8_t)(i >>  8);
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

		uint32_t x1 = out.m128i_u8[ 0];
		uint32_t x2 = out.m128i_u8[13];
		uint32_t x3 = out.m128i_u8[10];
		uint32_t x4 = out.m128i_u8[ 7];

		x1 = x1 <<  0;
		x2 = x2 <<  8;
		x3 = x3 << 16;
		x4 = x4 << 24;
		
		uint32_t diag = ( x1 | x2 | x3 | x4 );

		
		//mtx.lock();
		res[diag] = res[diag] + 1;
		//mtx.unlock();
	}


}

void printUsage(std::string name)
{
	std::cerr << "Usage: " << name << std::endl
		<< "\t\t<MODE>        FULL, PER_THREAD, TOTAL" << std::endl
		<< "\t\t<WORKLOAD>    Specifies the number of computations, depending on the mode. Ignored if MODE = FULL" << std::endl
		<< "\t\t<NUM_THREADS> Optional. Specifies the number of threads. Default = 1" << std::endl;

	std::cerr << std::endl << "\t\tExample: " << name << " FULL 0" << std::endl
		<< "\t\tStarts the differential distinguisher with 1 thread and does the full computation." << std::endl;

	std::cerr << std::endl << "\t\tExample: " << name << " TOTAL 50 3" << std::endl
		<< "\t\tStarts the differential distinguisher with 3 threads and does 50 computations in total." << std::endl;
}

StepSizeSetting parseSetting(std::string setting)
{
	for (auto & c : setting) c = toupper(c);
	if (strcmp(setting.c_str(), "PER_THREAD") == 0)
		return PER_THREAD;
	else if (strcmp(setting.c_str(), "TOTAL") == 0)
		return TOTAL;
	else
		return FULL;
}



#endif