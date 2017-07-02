#include "../Header/aesmain.h"
#include <stdio.h>

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


}