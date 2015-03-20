## Simple Interface ##
It's called 'simple' as opposed to the new structure-output interface. Also since it returns only text. If you wish to parse the results, you should not, and instead use the new structure-output interface.

This is the old interface from diStorm64, which is still accessible in diStorm3.

All the information in this page are taken from _distorm.h_.
If you want to see how to use this interface go to [CSample](CSample.md).

```
/* Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64. */
typedef enum {Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2} _DecodeType;
typedef OFFSET_INTEGER _OffsetType;

/* Static size of strings. Do not change this value. */
#define MAX_TEXT_SIZE (48)
typedef struct {
    unsigned int length;
    unsigned char p[MAX_TEXT_SIZE]; /* p is a null terminated string. */
} _WString;

/* 
  * Old decoded instruction structure in text format.
  * Used only for backward compatibility with diStorm64.
  * This structure holds all information the disassembler generates per instruction.
  */
typedef struct {
    _WString mnemonic; /* Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc. */
    _WString operands; /* Operands of the decoded instruction, up to 3 operands, comma-seperated. */
    _WString instructionHex; /* Hex dump - little endian, including prefixes. */
    unsigned int size; /* Size of decoded instruction. */
    _OffsetType offset; /* Start offset of the decoded instruction. */
} _DecodedInst;

/* Return code of the decoding function. */
typedef enum {DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR} _DecodeResult;
```

```
_DecodeResult distorm_decode(
    IN _OffsetType codeOffset,
    IN const unsigned char* code,
    IN int codeLen,
    IN _DecodeType dt,
    OUT _DecodedInst result[],
    IN unsigned int maxInstructions,
    OUT unsigned int* usedInstructionsCount);
```

  * **codeOffset** - Virtual address of the code in the disassembly listing. It is not an offset inside _code_! It is similar to the [org](org.md) directive of Assemblers.
  * **code** - Pointer to a block of memory to disassemble.
  * **codeLen** - The maximum number of bytes that can be read from _code_.
  * **dt** - Decoding mode, either Decode16Bits, Decode32Bits or Decode64Bits.
  * **result** - An array of DecodedInst structures that will be filled by the disassembler.
  * **maxInstructions** - The maximum number of instructions that _result_ can hold, which means, the number of instructions to read from the stream.
  * **usedInstructionsCount** - The number of instructions that were successfully decoded and written to _result_.

Return code (of type DecodeResult) -<br>
If the input was incorrect, like NULL pointers were passed, or negative <i>codeLen</i>, then the return code is DECRES_INPUTERR. This is only done to verify the input is alright.<br>
Otherwise, if all <b>bytes</b> in the stream were decoded the return code is DECRESS_SUCCESS.<br>
However, <b>important(!)</b>: if the return code is DECRES_MEMORYERR then it means there was not enough space to write more instructions into the <i>result</i> array. You still get as many as possible instructions written to <i>result</i>. Therefore in a case where you want to disassemble all instructions in the stream, you will have to call the disassembler once again after updating all pointers, etc. A good example of how to do this synchronization can be seen at <a href='http://code.google.com/p/distorm/source/browse/trunk/win32proj/main.cpp'>http://code.google.com/p/distorm/source/browse/trunk/win32proj/main.cpp</a>