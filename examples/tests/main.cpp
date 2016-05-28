// diStorm64 library sample
// http://ragestorm.net/distorm/
// Arkon, Stefan, 2005


#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "../../distorm.lib")

#include "../../include/distorm.h"

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (1000)

int main(int argc, char **argv)
{
	_DecodeResult res;
	_DecodedInst decodedInstructions[1000];
	unsigned int decodedInstructionsCount = 0, i = 0;
	_OffsetType offset = 0;
	unsigned int dver = distorm_version();
	printf("diStorm version: %d.%d.%d\n", (dver >> 16), ((dver) >> 8) & 0xff, dver & 0xff);

	unsigned char rawData[] = {

		0x68, 0, 0, 0, 0,
		0x9b,
		0xdf, 0xe0,
		0x66, 0xa1, 0xcc, 0xb0, 0x97, 0x7c,
		0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00,
		0xc7, 0xf8, 0xaa, 0xaa, 0xaa, 0xaa,
		0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00
} ;
	res = distorm_decode(offset, (const unsigned char*)rawData, sizeof(rawData), Decode64Bits, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
	for (int i = 0; i < decodedInstructionsCount; i++) {
		printf("%08I64x (%02d) %-24s %s%s%s\r\n", decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
	}

	return 0;
}
