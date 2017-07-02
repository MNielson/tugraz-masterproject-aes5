#pragma once
#include <stdint.h>


class AesMain
{
public:
	void expandKey(uint8_t* expandedKey, uint32_t expandedKeySize, const uint8_t* cipherKey, uint32_t keySize);
	void printBlock(uint8_t* block, uint8_t size);
	void aes(uint8_t* state, const uint8_t* key, int numRounds, bool skipFinalRound);
	void aesWithoutKeyExpansion(uint8_t* state, const uint8_t* expandedKey, int numRounds, bool skipFinalRound);

private:
	void rotate(uint8_t * word);
	void keyScheduleCore(uint8_t* word, int32_t iteration);
	void shiftRow(uint8_t* state, uint8_t nbr);
	void shiftRows(uint8_t* state);
	void addRoundKey(uint8_t* state, uint8_t* roundKey);
	uint8_t mulGaloisField2_8(uint8_t a, uint8_t b);
	void mixColumns(uint8_t* state);
	void mixColumn(uint8_t* column);
	void aesRound(uint8_t* state, uint8_t* roundKey);
	void subBytes(uint8_t* state);
	void finalRound(uint8_t* state, uint8_t* roundKey);
	void createRoundKey(const uint8_t* expandedKey, uint8_t* roundKey);
	

};
