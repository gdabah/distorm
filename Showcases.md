Here I'm going to show a few samples of the input and output of the new diStorm interface. This should give you a good idea of how to use the structures and what they contain. Note that the default decoding mode is 32 bits, unless specificed otherwise.

The following snippet shows how I called diStorm to decompose a single instruction:
```
_DInst decodedInstructions[1];
unsigned int decodedInstructionsCount = 0;
_DecodeType dt = Decode32Bits;
unsigned char buf[] = "\x90";

_CodeInfo ci;
ci.code = buf;
ci.codeLen = sizeof(buf);
ci.codeOffset = 0;
ci.dt = dt;
ci.features = DF_NONE;
distorm_decompose(&ci, decodedInstructions, 1, &decodedInstructionsCount);
```


---

If you want to learn how the _DInst is formatted take a look at [DecomposeInterface](DecomposeInterface.md), and come back later._

```
NOP:
		addr	0x0000000000000000
		size	0x01         ; 1 byte long instruction
		flags	0x00a0
		segment	0xff         ; not set
		base	0xff         ; not set
		scale	0x00
		dispSize	0x00
		opcode	0x0067       ; I_NOP
+		ops
		disp	0x0000000000000000
+		imm	{sbyte=0x00 byte=0x00 sword=0x0000 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08         ; META_GET_ISC(0x08): ISC_INTEGER
```

```
INC EAX:
		addr	0x0000000000000000
		size	0x01         ; 1 byte long instruction
		flags	0x00a0       ;
		segment	0xff
		base	0xff
		scale	0x00
		dispSize	0x00
		opcode	0x000f       ; I_INC
-		ops:
-			[0x0]	{type='' index='' size=0x0020 }	_Operand
				type	0x01         ; O_REG
				index	0x10         ; R_EAX
				size	0x0020       ; 32 bits register
+			[0x1]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+			[0x2]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+			[0x3]	{type=0x00 index=0x00 size=0x0000 }	_Operand
		disp	0x0000000000000000
+		imm	{sbyte=0x00 byte=0x00 sword=0x0000 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08
```

```
MOV EAX, 0x1:
		addr	0x0000000000000000
		size	0x05        ; 5 bytes long instruction
		flags	0x00a0
		segment	0xff
		base	0xff
		scale	0x00
		dispSize	0x00
		opcode	0x002a      ; I_MOV
-		ops:
-			[0x0]	{type='' index='' size=0x0020 }	_Operand
				type	0x01          ; O_REG
				index	0x10          ; R_EAX
				size	0x0020        ; 32 bits register
-			[0x1]	{type='' index=0x00 size=0x0020 }	_Operand
				type	0x02          ; O_IMM
				index	0x00          ; unused
				size	0x0020        ; 32 bits immediate
+			[0x2]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+			[0x3]	{type=0x00 index=0x00 size=0x0000 }	_Operand
		disp	0x0000000000000000
+		imm	{sbyte='' byte='' sword=0x0001 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08

```

```
MOV [EAX], AL:
		addr	0x0000000000000000
		size	0x02        ; 2 bytes long instruction
		flags	0x00a0
		segment	0xc7        ; SEGMENT_IS_DEFAULT(0xc7): TRUE, SEGMENT_GET(0xc7): R_DS
		base	0xff
		scale	0x00
		dispSize	0x00
		opcode	0x002a      ; I_MOV
-		ops:
-			[0x0]	{type='' index='' size=0x0008 }	_Operand
				type	0x06          ; O_SMEM
				index	0x10          ; R_EAX
				size	0x0008        ; size of memory access is 8 bits
-			[0x1]	{type='' index='0' size=0x0008 }	_Operand
				type	0x01          ; O_REG
				index	0x30          ; R_AL
				size	0x0008        ; 8 bits register
+		[0x2]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+		[0x3]	{type=0x00 index=0x00 size=0x0000 }	_Operand
		disp	0x0000000000000000
+		imm	{sbyte=0x00 byte=0x00 sword=0x0000 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08
```

```
MOV EDI, [EAX+0x12345678]:
		addr	0x0000000000000000
		size	0x06
		flags	0x00a0
		segment	0xc7        ; SEGMENT_IS_DEFAULT(0xc7): TRUE, SEGMENT_GET(0xc7): R_DS
		base	0xff
		scale	0x00
		dispSize	0x20   ; the size of the displacement value in bits is 32
		opcode	0x002a
-		ops:
-			[0x0]	{type='' index='' size=0x0020 }	_Operand
				type	0x01            ; O_REG
				index	0x17            ; R_EDI
				size	0x0020          ; 32 bits register
-			[0x1]	{type='' index='' size=0x0020 }	_Operand
				type	0x06            ; O_SMEM
				index	0x10            ; R_EAX
				size	0x0020          ; size of memory access is 32 bits
+		[0x2]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+		[0x3]	{type=0x00 index=0x00 size=0x0000 }	_Operand
		disp	0x0000000012345678              ; relative offset = 0x12345678 
+		imm	{sbyte=0x00 byte=0x00 sword=0x0000 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08
```

```
MOV EDI, [EBP+EAX*4+0x12345678]:
		addr	0x0000000000000000
		size	0x07
		flags	0x00a0
		segment	0xc6           ; SEGMENT_IS_DEFAULT(0xc6): TRUE, SEGMENT_GET(0xc6): R_SS
		base	0x15           ; base register: R_EBP
		scale	0x04           ; scale: 4
		dispSize	0x20   ; the size of the displacement value in bits is 32
		opcode	0x002a         ; I_MOV
-		ops:
-			[0x0]	{type='' index='' size=0x0020 }	_Operand
				type	0x01      ; O_REG
				index	0x17      ; R_EDI
				size	0x0020    ; 32 bits register
-			[0x1]	{type='' index='' size=0x0020 }	_Operand
				type	0x07      ; O_MEM
				index	0x10      ; R_EAX
				size	0x0020    ; size of memory access is 32 bits
+		[0x2]	{type=0x00 index=0x00 size=0x0000 }	_Operand
+		[0x3]	{type=0x00 index=0x00 size=0x0000 }	_Operand
		disp	0x0000000012345678        ; relative offset is 0x12345678
+		imm	{sbyte=0x00 byte=0x00 sword=0x0000 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x08
```

```
JMP 0x105:
		addr	0x0000000000000000
		size	0x05
		flags	0x00a0
		segment	0xff
		base	0xff
		scale	0x00
		dispSize	0x00
		opcode	0x0053         ; I_JMP
+		ops
		disp	0x0000000000000000
+		imm	{sbyte=0x00 byte=0x00 sword=0x0100 ...}	_Value
		unusedPrefixesMask	0x0000
		meta	0x0c           ; META_GET_ISC(0x0c): ISC_INTEGER, META_GET_FC(0x0c): FC_BRANCH
```


---

```
Original function in C:
int f(int a, int b)
{
	return a + b;
}

Compiled and assembled into:
0x55 0x8b 0xec 0x8b 0x45 0x08 0x03 0x45 0x0c 0xc9 0xc3

Basic API distorm_decode result:

-	disassembled[0]
+		mnemonic	{length=4 p="PUSH" }
+		operands	{length=3 p="EBP" }
+		instructionHex	{length=2 p="55" }
		size	1
		offset	0

-	disassemled[1]
+		mnemonic	{length=3 p="MOV" }
+		operands	{length=8 p="EBP, ESP" }
+		instructionHex	{length=4 p="8bec" }
		size	2
		offset	1

-	disassembled[2]
+		mnemonic	{length=3 p="MOV" }
+		operands	{length=14 p="EAX, [EBP+0x8]" }
+		instructionHex	{length=6 p="8b4508" }
		size	3
		offset	3

-	disassembled[3]
+		mnemonic	{length=3 p="ADD" }
+		operands	{length=14 p="EAX, [EBP+0xc]" }
+		instructionHex	{length=6 p="03450c" }
		size	3
		offset	6

-	disassembled[4]
+		mnemonic	{length=5 p="LEAVE" }
+		operands	{length=0 p="" }
+		instructionHex	{length=2 p="c9" }
		size	1
		offset	9

-	disassembled[5]
+		mnemonic	{length=3 p="RET" }
+		operands	{length=0 p="" }
+		instructionHex	{length=2 p="c3" }
		size	1
		offset	10

New API distorm_decompose result:

- decomposed[0]
		addr	0
		size	1
		flags	1280 - FLAG_GET_OPSIZE(1280): Decode32Bits, FLAG_GET_ADDRSIZE(1280): Decode32Bits
		segment	R_NONE
		base	R_NONE
		scale	0
		dispSize	0
		opcode	I_PUSH
-		ops[0]
			type	O_REG
			index	R_EBP
			size	32
		disp	0
		imm	0
		unusedPrefixesMask	0
		meta	8 - META_GET_ISC(8): ISC_INTEGER
		usedRegistersMask	32

- decomposed[1]
		addr	1
		size	2
		flags	1344 - FLAG_DST_WR, FLAG_GET_OPSIZE(1280): Decode32Bits, FLAG_GET_ADDRSIZE(1280): Decode32Bits
		segment	R_NONE
		base	R_NONE
		scale	0
		dispSize	0
		opcode	I_MOV
-		ops[0]
			type	O_REG
			index	R_EBP
			size	32
-		ops[1]
			type	O_REG
			index	R_ESP
			size	32
		disp	0
		imm	0
		unusedPrefixesMask	0
		meta	8 - META_GET_ISC(8): ISC_INTEGER
		usedRegistersMask	48

- decomposed[2]
		addr	3
		size	3
		flags	1344 - FLAG_DST_WR, FLAG_GET_OPSIZE(1280): Decode32Bits, FLAG_GET_ADDRSIZE(1280): Decode32Bits
		segment	198 - SEGMENT_IS_DEFAULT(198): TRUE, SEGMENT_GET(198): R_SS
		base	R_NONE
		scale	0
		dispSize	8
		opcode	I_MOV
-		ops[0]
			type	O_REG
			index	R_EAX
			size	32
-		ops[1]
			type	O_SMEM
			index	R_EBP
			size	32
		disp	8
		imm	0
		unusedPrefixesMask	0
		meta	8 - META_GET_ISC(8): ISC_INTEGER
		usedRegistersMask	33

-decomposed[3]
		addr	6
		size	3
		flags	1344
		segment	198 - SEGMENT_IS_DEFAULT(198): TRUE, SEGMENT_GET(198): R_SS
		base	R_NONE
		scale	0
		dispSize	8
		opcode	I_ADD
-		ops[0]
			type	O_REG
			index	R_EAX
			size	32
-		ops[1]
			type	O_SMEM
			index	R_EBP
			size	32
		disp	12
		imm	0
		unusedPrefixesMask	0
		meta	8 - META_GET_ISC(8): ISC_INTEGER
		usedRegistersMask	33

-decomposed[4]
		addr	9
		size	1
		flags	1280 - FLAG_GET_OPSIZE(1280): Decode32Bits, FLAG_GET_ADDRSIZE(1280): Decode32Bits
		segment	R_NONE
		base	R_NONE
		scale	0
		dispSize	0
		opcode	I_LEAVE
		ops	0
		disp	0
		imm	0
		unusedPrefixesMask	0
		meta	8 - META_GET_ISC(8): ISC_INTEGER
		usedRegistersMask	0

-decomposed[5]
		addr	10
		size	1
		flags	1280 - FLAG_GET_OPSIZE(1280): Decode32Bits, FLAG_GET_ADDRSIZE(1280): Decode32Bits
		segment	R_NONE
		base	R_NONE
		scale	0
		dispSize	0
		opcode	I_RET
		ops	0
		disp	0
		imm	0
		unusedPrefixesMask	0
		meta	10 - META_GET_ISC(10): ISC_INTEGER, META_GET_FC(10): FC_RET
		usedRegistersMask	0
```