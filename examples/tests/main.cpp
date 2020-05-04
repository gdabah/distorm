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
	_DInst decodedInstructions[1000];
	_DecodedInst di;
	unsigned int decodedInstructionsCount = 0, i = 0;
	_OffsetType offset = 0;
	unsigned int dver = distorm_version();
	printf("diStorm version: %d.%d.%d\n", (dver >> 16), ((dver) >> 8) & 0xff, dver & 0xff);

	unsigned char rawData[6] = {
		0xC4, 0xE3, 0x79, 0x14, 0xD0, 0x03
	};

	_CodeInfo ci = { 0 };
	ci.codeLen = sizeof(rawData);
	ci.code = rawData;
	ci.dt = Decode64Bits;
	ci.features = 0;
	distorm_decompose(&ci, decodedInstructions, 1000, &decodedInstructionsCount);
	//distorm_decode(0, rawData, sizeof(rawData), Decode32Bits, &di, 1, &decodedInstructionsCount);
	for (int i = 0; i < decodedInstructionsCount; i++) {
		distorm_format(&ci, &decodedInstructions[i], &di);
		printf("%08I64x (%02d) %-24s %s%s%s\r\n", di.offset, di.size, (char*)di.instructionHex.p, (char*)di.mnemonic.p, di.operands.length != 0 ? " " : "", (char*)di.operands.p);
	}

	return 0;
}
