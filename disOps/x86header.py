#
# x86header.py
#
# Copyright (C) 2009 Gil Dabah, http://ragestorm.net/disops/
#

class OperandType:
	""" Types of possible operands in an opcode.
	Refer to the diStorm's documentation or diStorm's instructions.h
	for more explanation about every one of them. """
	(NONE,
	# REG only operands:
	IMM8,
	IMM16,
	IMM_FULL,
	IMM32,
	SEIMM8,
	REG8,
	REG16,
	REG_FULL,
	REG32,
	REG32_64,
	ACC8,
	ACC16,
	ACC_FULL,
	ACC_FULL_NOT64,
	RELCB,
	RELC_FULL,
	IB_RB,
	IB_R_FULL,
	MOFFS8,
	MOFFS_FULL,
	REGI_ESI,
	REGI_EDI,
	REGI_EBXAL,
	REGI_EAX,
	REGDX,
	REGECX,
	FPU_SI,
	FPU_SSI,
	FPU_SIS,
	XMM,
	XMM_RM,
	REGXMM0,
	WREG32_64,
	VXMM,
	XMM_IMM,
	YXMM,
	YXMM_IMM,
	YMM,
	VYMM,
	VYXMM,
	CONST1,
	REGCL,
	CREG,
	DREG,
	SREG,
	SEG,
	IMM16_1,
	IMM8_1,
	IMM8_2,
	PTR16_FULL,
	FREG32_64_RM,
	MM,
	MM_RM,
	# MEM only operands:
	MEM,
	MEM32,
	MEM32_64,
	MEM64,
	MEM64_128,
	MEM128,
	MEM16_FULL,
	MEM16_3264,
	MEM_OPT,
	FPUM16,
	FPUM32,
	FPUM64,
	FPUM80,
	LMEM128_256,
	# MEM & REG operands ahead:
	RM8,
	RM16,
	RM32,
	RFULL_M16,
	RM_FULL,
	WRM32_64,
	R32_64_M8,
	R32_64_M16,
	RM32_64,
	RM16_32,
	R32_M8,
	R32_M16,
	REG32_64_M8,
	REG32_64_M16,
	MM32,
	MM64,
	XMM16,
	XMM32,
	XMM64,
	XMM128,
	WXMM32_64,
	YMM256,
	YXMM64_256,
	YXMM128_256,
	LXMM64_128) = range(93)

class OpcodeLength:
	""" The length of the opcode in bytes.
	Where a suffix of '3' means we have to read the REG field of the ModR/M byte (REG size is 3 bits).
	Suffix of 'd' means it's a Divided instruction (see documentation),
	tells the disassembler to read the REG field or the whole next byte.

	OL_33 and OL_4 are used in raw opcode bytes, they include the mandatory prefix,
	therefore when they are defined in the instruction tables, the mandatory prefix table is added,
	and they become OL_23 and OL_3 correspondingly. There is no effective opcode which is more than 3 bytes. """
	(OL_1,  # 0
	OL_13,  # 1
	OL_1d,  # 2 - Can be prefixed (only by WAIT/9b)
	OL_2,   # 3 - Can be prefixed
	OL_23,  # 4 - Can be prefixed
	OL_2d,  # 5
	OL_3,   # 6 - Can be prefixed
	OL_33,  # 7 - Internal only
	OL_4    # 8 - Internal only
	) = range(9)

	""" Next-Opcode-Length dictionary is used in order to recursively build the instructions' tables dynamically.
	It is used in such a way that it indicates how many more nested tables
	we have to build and link starting from a given OL. """
	NextOL = {OL_13: OL_1, OL_1d: OL_1, OL_2: OL_1, OL_23: OL_13,
		  OL_2d: OL_1d, OL_3: OL_2, OL_33: OL_23, OL_4: OL_3}

class InstFlag:
	""" Instruction Flag contains all bit mask constants for describing an instruction.
	You can bitwise-or the flags. See diStorm's documentation for more explanation.

	The GEN_BLOCK is a special flag, it is used in the tables generator only;
	See GenBlock class inside x86db.py. """
	FLAGS_EX_START_INDEX = 32
	INST_FLAGS_NONE = 0
	(MODRM_REQUIRED,        # 0
	NOT_DIVIDED,            # 1
	_16BITS,                # 2
	_32BITS,                # 3
	PRE_LOCK,               # 4
	PRE_REPNZ,              # 5
	PRE_REP,                # 6
	PRE_CS,                 # 7
	PRE_SS,                 # 8
	PRE_DS,                 # 9
	PRE_ES,                 # 10
	PRE_FS,                 # 11
	PRE_GS,                 # 12
	PRE_OP_SIZE,            # 13
	PRE_ADDR_SIZE,          # 14
	NATIVE,                 # 15
	USE_EXMNEMONIC,         # 16
	USE_OP3,                # 17
	USE_OP4,                # 18
	MNEMONIC_MODRM_BASED,   # 19
	MODRR_REQUIRED,         # 20
	_3DNOW_FETCH,           # 21
	PSEUDO_OPCODE,          # 22
	INVALID_64BITS,         # 23
	_64BITS,                # 24
	PRE_REX,                # 25
	USE_EXMNEMONIC2,        # 26
	_64BITS_FETCH,          # 27
	FORCE_REG0,             # 28
	PRE_VEX,                # 29
	MODRM_INCLUDED,         # 30
	DST_WR,                 # 31
	VEX_L,                  # 32 From here on: flagsEx.
	VEX_W,                  # 33
	MNEMONIC_VEXW_BASED,    # 34
	MNEMONIC_VEXL_BASED,    # 35
	FORCE_VEXL,             # 36
	MODRR_BASED,            # 37
	VEX_V_UNUSED,           # 38
	GEN_BLOCK,              # 39 From here on: internal to disOps.
	EXPORTED                # 40
	) = [1 << i for i in range(41)]
	# Nodes are extended if they have any of the following flags:
	EXTENDED = (PRE_VEX | USE_EXMNEMONIC | USE_EXMNEMONIC2 | USE_OP3 | USE_OP4)
	SEGMENTS = (PRE_CS | PRE_SS | PRE_DS | PRE_ES | PRE_FS | PRE_FS)

class ISetClass:
	""" Instruction-Set-Class indicates to which set the instruction belongs.
	These types are taken from the documentation of Intel/AMD. """
	(INTEGER,
	FPU,
	P6,
	MMX,
	SSE,
	SSE2,
	SSE3,
	SSSE3,
	SSE4_1,
	SSE4_2,
	SSE4_A,
	_3DNOW,
	_3DNOWEXT,
	VMX,
	SVM,
	AVX,
	FMA,
	CLMUL,
	AES) = range(1, 20)

class FlowControl:
	""" The flow control instruction will be flagged in the lo byte of the 'meta' field in _InstInfo of diStorm.
	They are used to distinguish between flow control instructions (such as: ret, call, jmp, jz, etc) to normal ones. """
	(CALL,
	RET,
	SYS,
	UNC_BRANCH,
	CND_BRANCH,
	INT,
	CMOV,
	HLT) = range(1, 9)

class NodeType:
	""" A node can really be an object holder for an instruction-info object or
	another table (list) with a different size.

	GROUP - 8 entries in the table
	FULL - 256 entries in the table.
	Divided - 72 entries in the table (ranges: 0x0-0x7, 0xc0-0xff).
	Prefixed - 12 entries in the table (none, 0x66, 0xf2, 0xf3). """
	(NONE,        # 0
	INFO,         # 1
	INFOEX,       # 2
	INFO_TREAT,   # 3
	LIST_GROUP,   # 4
	LIST_FULL,    # 5
	LIST_DIVIDED, # 6
	LIST_PREFIXED # 7
	) = range(0, 8)

class CPUFlags:
	""" Specifies all the flags that the x86/x64 CPU supports, in a special compact order. """
	(CF, # 0
	IF,  # 1
	PF,  # 2
	DF,  # 3
	AF,  # 4
	OF,  # 5
	ZF,  # 6
	SF   # 7
	) = [1 << i for i in range(8)]
