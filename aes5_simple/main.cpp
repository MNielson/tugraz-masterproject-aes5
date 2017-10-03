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
#include <string>
#include <iostream>
#include <fstream>

#define TWO_P_32 4294967296
#define BUFFER_SIZE 64
#define SAMPLES 8
#define INTER_RES 4


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

typedef struct {
	double mean;
	double variance;
	double skew;
} StatisticResult;


std::string toString(uint8_t block[16])
{
	std::string str = "";
	char buffer[100];
	for (int i = 0; i < 16; i = i + 4)
	{
		sprintf_s(buffer, "%X %X %X %X\n", block[i], block[i + 1], block[i + 2], block[i + 3]);
		str += buffer;
	}
	return str;
}

std::string toString(StatisticResult s)
{
	std::string str = "";
	char buffer[100];
	sprintf_s(buffer, "mean: %f\n", s.mean);
	str += buffer;
	sprintf_s(buffer, "variance: %f\n", s.variance);
	str += buffer;
	sprintf_s(buffer, "skew: %f\n", s.skew);
	str += buffer;
	return str;
}

std::string toString(uint64_t value) {
	std::ostringstream os;
	os << value;
	return os.str();
}

std::string toString(Sample s)
{
	std::string str = "";
	char buffer[1000];
	sprintf_s(buffer, "collisions: %s\n", toString(s.collisions).c_str());
	str += buffer;
	sprintf_s(buffer, "constant:\n%s", toString(s.con).c_str());
	str += buffer;
	sprintf_s(buffer, "key:\n%s", toString(s.key).c_str());
	str += buffer;
	return str;
}

void toFile(Sample* s, int elements, char* fileName)
{
	std::ofstream file;
	file.open(fileName);
	if (file.is_open())
	{
		file << elements << " samples" << std::endl;
		for (int i = 0; i < elements; i++)
		{
			file << "## Sample " << i << " ##" << std::endl;
			file << toString(s[i]);
		}
		file.close();
	}	
	return;
}

void toFile(StatisticResult* s, int elements, char* fileName)
{
	std::ofstream file;
	file.open(fileName);
	if (file.is_open())
	{
		file << elements << " Results" << std::endl;
		for (int i = 0; i < elements; i++)
		{
			file << "## Result " << i << " ##" << std::endl;
			file << "Calculated from " << (i+1) * INTER_RES << " samples" << std::endl;
			file << toString(s[i]);
		}
		file.close();
	}
	return;
}

uint64_t aesDistinguisherWorker(uint8_t* res, __m128i key, uint8_t* con)
{
	uint8_t v0 = 0;
	uint8_t v5 = 0;
	uint8_t v10 = 0;
	uint8_t v15 = 0;
	__m128i mes128;
	__m128i* resMem = (__m128i *)aligned_malloc(128, 16);
	if (resMem == NULL)
		throw std::invalid_argument("NULL pointer receive.");


	__m128i expKey[6];
	expKey[0] = _mm_load_si128((__m128i*)(&key));
	expKey[1] = KEYEXP(expKey[0], 0x01);
	expKey[2] = KEYEXP(expKey[1], 0x02);
	expKey[3] = KEYEXP(expKey[2], 0x04);
	expKey[4] = KEYEXP(expKey[3], 0x08);
	expKey[5] = KEYEXP(expKey[4], 0x10);

	uint32_t* buffer = (uint32_t*)calloc(BUFFER_SIZE, sizeof(uint32_t));
	if (buffer == NULL)
		throw std::invalid_argument("NULL pointer receive.");

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
		std::cerr << "Error: " << collisions << " is not a multiple of 8." << std::endl;

	return collisions;
}

Sample aesDistinguisher(uint8_t* res, uint64_t memSize)
{
	memset(res, 0, memSize);
	Sample sample;

	srand((unsigned int)time(NULL));
	// generate random key

	for (int i = 0; i < 16; ++i)
		sample.key[i] = rand();
	__m128i key128 = _mm_setr_epi8(sample.key[15], sample.key[14], sample.key[13], sample.key[12], sample.key[11], sample.key[10], sample.key[9], sample.key[8], sample.key[7], sample.key[6], sample.key[5], sample.key[4], sample.key[3], sample.key[2], sample.key[1], sample.key[0]);

	// generate random const
	for (int i = 0; i < 16; ++i)
		sample.con[i] = rand();

	sample.collisions = aesDistinguisherWorker(res, key128, sample.con);
	return sample;
}

StatisticResult computeStatistics(Sample* samples, uint64_t numSample)
{
	StatisticResult sRes;

	//compute mean
	double tMean = 0;
	for (uint64_t i = 0; i < numSample; i++)
	{
		tMean += samples[i].collisions;
	}	
	sRes.mean = tMean / numSample;

	//compute variance
	double tVariance = 0;
	for (uint64_t i = 0; i < numSample; i++)
	{
		tVariance += pow(samples[i].collisions - sRes.mean, 2);
	}
	sRes.variance = tVariance / (numSample - 1);

	//compute skew
	double tL = 0;
	for (uint64_t i = 0; i < numSample; i++)
	{
		tL += pow(samples[i].collisions - sRes.mean, 3);
	}
	double tSkew = tL / numSample;
	sRes.skew = tSkew / pow(sRes.variance, 1.5);

	return sRes;
}

int main(int argc, char* argv[])
{
	uint8_t* res = (uint8_t*)calloc(TWO_P_32, sizeof(uint8_t));
	if (res == NULL)
		throw std::invalid_argument("NULL pointer receive.");

	Sample* samples = (Sample*)calloc(SAMPLES, sizeof( Sample));
	if (samples == NULL)
		throw std::invalid_argument("NULL pointer receive.");

	StatisticResult* statisticResults = (StatisticResult*)calloc(SAMPLES / INTER_RES, sizeof(StatisticResult));
	if (statisticResults == NULL)
		throw std::invalid_argument("NULL pointer receive.");

	int j = 0;
	auto begin = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < SAMPLES; i++)
	{
		samples[i] = aesDistinguisher(res, TWO_P_32 * sizeof(uint8_t));
		std::cout << samples[i].collisions << std::endl;
		if (samples[i].collisions % 8)
			std::cout << ":(" << std::endl;

		if ((i + 1) % INTER_RES == 0)
		{
			statisticResults[j] = computeStatistics(samples, i + 1);
			char filename[100];
			sprintf_s(filename, "StatisticsResult%d.txt", j+1);
			toFile(statisticResults, j+1, filename);
#ifdef DEBUG
			char filenameSamples[100];
			sprintf_s(filenameSamples, "Samples%d.txt", i + 1);
			toFile(filenameSamples, "Samples", i+1)
#endif // DEBUG

			
			std::cout << "Mean: " << statisticResults[j].mean << std::endl;
			std::cout << "Variance: " << statisticResults[j].variance << std::endl;
			std::cout << "Skew: " << statisticResults[j].skew << std::endl;
			j = j + 1;
		}
	}
	auto end   = std::chrono::high_resolution_clock::now();

	std::cout << "Finished work in " << std::chrono::duration_cast<std::chrono::minutes>(end - begin).count() << " minutes." << std::endl;

	delete[] res;
	delete[] samples;
	delete[] statisticResults;
	return 0;
}

#endif