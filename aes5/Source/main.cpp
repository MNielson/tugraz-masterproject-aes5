#include "../Header/aes_main.h"
#include <stdio.h>

void main()
{

	uint8_t key[16] = { 0 };
	uint8_t data[16] = { 0 };
	uint8_t expandedKey[176];
	expandKey(expandedKey, 176, key, 16);

	printf("Key: \n");
	printBlock(key, 16);
	printf("\nData In: \n");
	printBlock(data, 16);
	aesWithoutKeyExpansion(data, expandedKey, 10, false);
	printf("\nData Out: \n");
	printBlock(data, 16);


}