diStorm3 is backward compatible with diStorm64.
In this page I will show how to use diStorm64's interface, which only returns text.

To see the function declarations go to [Simple Interface](SimpleInterface.md).

For a more complete code sample in Windows see: http://code.google.com/p/distorm/source/browse/trunk/examples/win32/main.cpp

And for Linux:
http://code.google.com/p/distorm/source/browse/trunk/examples/linux/main.c

Always start with:
```
#include "distorm.h"
```

In Windows you might need to link the library using the following line:
```
#pragma comment(lib, "distorm.lib") 
```

```
// How many instructions to allocate on stack.
#define MAX_INSTRUCTIONS 32

// Holds the result of the decoding.
_DecodeResult res;

// Default offset for buffer is 0.
_OffsetType offset = 0;

// Decoded instruction information - the Decode will write the results here.
_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];

// decodedInstructionsCount indicates how many instructions were written to the result array.
unsigned int decodedInstructionsCount = 0;

// Default decoding mode is 32 bits.
_DecodeType dt = Decode32Bits;

unsigned char buf[] = "\x90\x90\x90\x33\xc0\x66\xb8\x34\x12\x50\x40\xc3";

// Decode the buffer at given offset (virtual address).
res = distorm_decode(offset, (const unsigned char*)buf, sizeof(buf), dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
if (res == DECRES_INPUTERR) { 
 // Error handling...
```

Note that even on error handling, you still should read the output normally!
So error really means that the array wasn't big enough.

```
} 
for (i = 0; i < decodedInstructionsCount; i++) { 
    printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p); 
}
```
