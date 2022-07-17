{
/* diStorm 3.5.2 */

/*
distorm.h

diStorm3 - Powerful disassembler for X86/AMD64
http://ragestorm.net/distorm/
distorm at gmail dot com
Copyright (C) 2003-2021 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/

================================================================================
Delphi port: Alexander (Rouse_) Bagel. May 2016.
Update to 3.5.2b: July 2022
WARNINIG: Support Delphi XE2 and higher
https://github.com/AlexanderBagel/distorm
================================================================================
}

unit distorm;

interface

uses
  Windows,
  SysUtils,
  Classes;

  // 0. Open distorm solution in Microsoft Visual Studio
  // 1. Remove "Security Check" from Project -> Properties -> C/C++ -> Code Generation
  // 2. Build "clib" configuration
  {$IFDEF WIN32}
    {$L ..\..\..\make\win32\clib\insts.obj}
    {$L ..\..\..\make\win32\clib\mnemonics.obj}
    {$L ..\..\..\make\win32\clib\decoder.obj}
    {$L ..\..\..\make\win32\clib\distorm.obj}
    {$L ..\..\..\make\win32\clib\instructions.obj}
    {$L ..\..\..\make\win32\clib\operands.obj}
    {$L ..\..\..\make\win32\clib\prefix.obj}
    {$L ..\..\..\make\win32\clib\textdefs.obj}
  {$ELSE}
    {$L ..\..\..\make\win32\x64\clib\insts.obj}
    {$L ..\..\..\make\win32\x64\clib\mnemonics.obj}
    {$L ..\..\..\make\win32\x64\clib\decoder.obj}
    {$L ..\..\..\make\win32\x64\clib\distorm.obj}
    {$L ..\..\..\make\win32\x64\clib\instructions.obj}
    {$L ..\..\..\make\win32\x64\clib\operands.obj}
    {$L ..\..\..\make\win32\x64\clib\prefix.obj}
    {$L ..\..\..\make\win32\x64\clib\textdefs.obj}
  {$ENDIF}

type

{/*
 * 64 bit offsets support:
 * If the diStorm library you use was compiled with 64 bits offsets,
 * make sure you compile your own code with the following macro set:
 * SUPPORT_64BIT_OFFSET
 * Otherwise comment it out, or you will get a linker error of an unresolved symbol...
 * Turned on by default!
 */}

 //* Define this macro for outer projects by default. */
 {$DEFINE SUPPORT_64BIT_OFFSET}

 {$IFDEF SUPPORT_64BIT_OFFSET}
 OFFSET_INTEGER = Uint64;
 {$ELSE}
 //* 32 bit offsets are used. */
 OFFSET_INTEGER = Uint64;
 {$ENDIF}

 // MACROS declaration lower ----->

  //* Decodes modes of the disassembler, 16 bits or 32 bits or 64 bits for AMD64, x86-64. */
  _DecodeType = (Decode16Bits = 0, Decode32Bits = 1, Decode64Bits = 2);

  _OffsetType = OFFSET_INTEGER;

  PCodeInfo = ^TCodeInfo;
  _CodeInfo = record
    codeOffset, addrMask: _OffsetType;
    nextOffset: _OffsetType; // nextOffset is OUT only.
    code: PByte;
    codeLen: Integer; // Using signed integer makes it easier to detect an underflow.
    dt: _DecodeType;
    features: UInt32;
  end;
  TCodeInfo = _CodeInfo;

  _OperandType = (O_NONE, O_REG, O_IMM, O_IMM1, O_IMM2, O_DISP, O_SMEM, O_MEM, O_PC, O_PTR);

  // Used by O_PTR
  _ptr = record
    seg: UInt16;
    // Can be 16 or 32 bits, size is in ops[n].size.
    off: UInt32;
  end;

  // Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only
  _ex = record
    i1, i2: UInt32;
  end;

  _Value = record
    case Integer of
      0: (sbyte: Int8);
      1: (ubyte: UInt8);
      2: (sword: Int16);
      3: (uword: UInt16);
      4: (sdword: Int32);
      5: (udword: UInt32);
      6: (sqword: Int64); // All immediates are SIGN-EXTENDED to 64 bits!
      7: (uqword: Uint64);

      // Used by O_PC: (Use GET_TARGET_ADDR).
      8: (addr: _OffsetType); // It's a relative offset as for now.

      // Used by O_PTR:
      9: (ptr: _ptr);

      // Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only.
      10: (ex: _ex);
    end;

  _Operand = record
{	 Type of operand:
		O_NONE: operand is to be ignored.
		O_REG: index holds global register index.
		O_IMM: instruction.imm.
		O_IMM1: instruction.imm.ex.i1.
		O_IMM2: instruction.imm.ex.i2.
		O_DISP: memory dereference with displacement only, instruction.disp.
		O_SMEM: simple memory dereference with optional displacement (a single register memory dereference).
		O_MEM: complex memory dereference (optional fields: s/i/b/disp).
		O_PC: the relative address of a branch instruction (instruction.imm.addr).
		O_PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
    }
    _type: UInt8; // _OperandType

{  Index of:
		O_REG: holds global register index
		O_SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
		O_MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
	  }
    index: UInt8;

{	 Size in bits of:
		O_REG: register
		O_IMM: instruction.imm
		O_IMM1: instruction.imm.ex.i1
		O_IMM2: instruction.imm.ex.i2
		O_DISP: instruction.disp
		O_SMEM: size of indirection.
		O_MEM: size of indirection.
		O_PC: size of the relative offset
		O_PTR: size of instruction.imm.ptr.off (16 or 32)
	  }
    size: UInt16;
  end;

const
  OPCODE_ID_NONE = 0;
  // Instruction could not be disassembled.
  FLAG_NOT_DECODABLE = UInt16(-1);
  // The instruction locks memory access.
  FLAG_LOCK = 1;
  // The instruction is prefixed with a REPNZ.
  FLAG_REPNZ = 1 shl 1;
  // The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
  FLAG_REP = 1 shl 2;
  // Indicates there is a hint taken for Jcc instructions only.
  FLAG_HINT_TAKEN = 1 shl 3;
  // Indicates there is a hint non-taken for Jcc instructions only.
  FLAG_HINT_NOT_TAKEN = 1 shl 4;
  // The Imm value is signed extended (E.G in 64 bit decoding mode, a 32 bit imm is usually sign extended into 64 bit imm).
  FLAG_IMM_SIGNED = 1 shl 5;
  // The destination operand is writable.
  FLAG_DST_WR = 1 shl 6;
  // The instruction uses RIP-relative indirection.
  FLAG_RIP_RELATIVE = 1 shl 7;

  // See flag FLAG_GET_XXX macros above.

  // The instruction is privileged and can only be used from Ring0.
  FLAG_PRIVILEGED_INSTRUCTION = 1 shl 15;

  // No register was defined.
  R_NONE = UInt8(-1);

  REGS64_BASE = 0;
  REGS32_BASE = 16;
  REGS16_BASE = 32;
  REGS8_BASE = 48;
  REGS8_REX_BASE = 64;
  SREGS_BASE = 68;
  FPUREGS_BASE = 75;
  MMXREGS_BASE = 83;
  SSEREGS_BASE = 91;
  AVXREGS_BASE = 107;
  CREGS_BASE = 123;
  DREGS_BASE = 132;

  OPERANDS_NO = 4;

type
  PDInst = ^TDInst;
  _DInst = record
    // Used by ops[n].type == O_IMM/O_IMM1&O_IMM2/O_PTR/O_PC. Its size is ops[n].size.
    imm: _Value;
    // Used by ops[n].type == O_SMEM/O_MEM/O_DISP. Its size is dispSize.
    disp: UInt64;
    // Virtual address of first byte of instruction.
    addr: _OffsetType;
    // General flags of instruction, holds prefixes and more, if FLAG_NOT_DECODABLE, instruction is invalid.
    flags: UInt16;
    // Unused prefixes mask, for each bit that is set that prefix is not used (LSB is byte [addr + 0]).
    unusedPrefixesMask: UInt16;
    // Mask of registers that were used in the operands, only used for quick look up, in order to know *some* operand uses that register class.
    usedRegistersMask: UInt32;
    // ID of opcode in the global opcode table. Use for mnemonic look up.
    opcode: UInt16;
    // Up to four operands per instruction, ignored if ops[n].type == O_NONE.
    ops: array [0..OPERANDS_NO - 1] of _Operand;
    // Number of valid ops entries.
    opsNo: UInt8;
    // Size of the whole instruction in bytes.
    size: UInt8;
    // Segment information of memory indirection, default segment, or overriden one, can be -1. Use SEGMENT macros.
    segment: UInt8;
    // Used by ops[n].type == O_MEM. Base global register index (might be R_NONE), scale size (2/4/8), ignored for 0 or 1.
    base, scale: UInt8;
    dispSize: UInt8;
    // Meta defines the instruction set class, and the flow control flags. Use META macros.
    meta: UInt16;
    // The CPU flags that the instruction operates upon, set only with DF_FILL_EFLAGS enabled, otherwise 0.
    modifiedFlagsMask, testedFlagsMask, undefinedFlagsMask: Uint16;
  end;
  TDInst = _DInst;

  //* ***  Helper Macros  *** */

  //* Get the ISC of the instruction, used with the definitions below. */
  //#define META_GET_ISC(meta) (((meta) >> 8) & 0x1f)
  function META_GET_ISC(meta: UInt16): UInt8;
  //#define META_SET_ISC(di, isc) (((di)->meta) |= ((isc) << 8))
  procedure META_SET_ISC(di: PDInst; isc: UInt8);
  //* Get the flow control flags of the instruction, see 'features for decompose' below. */
  //#define META_GET_FC(meta) ((meta) & 0xf)
  function META_GET_FC(meta: UInt16): UInt8;

  //* Get the target address of a branching instruction. O_PC operand type. */
  //#define INSTRUCTION_GET_TARGET(di) ((_OffsetType)(((di)->addr + (di)->imm.addr + (di)->size)))
  function INSTRUCTION_GET_TARGET(di: PDInst): _OffsetType;
  //* Get the target address of a RIP-relative memory indirection. */
  //#define INSTRUCTION_GET_RIP_TARGET(di) ((_OffsetType)(((di)->addr + (di)->disp + (di)->size)))
  function INSTRUCTION_GET_RIP_TARGET(di: PDInst): _OffsetType;

///*
// * Operand Size or Adderss size are stored inside the flags:
// * 00 - 16 bits
// * 01 - 32 bits
// * 10 - 64 bits
// * 11 - reserved
// *
// * If you call these set-macros more than once, you will have to clean the bits before doing so.
// */

  //#define FLAG_SET_OPSIZE(di, size) ((di->flags) |= (((size) & 3) << 8))
  procedure FLAG_SET_OPSIZE(di: PDInst; size: UInt8);
  //#define FLAG_SET_ADDRSIZE(di, size) ((di->flags) |= (((size) & 3) << 10))
  procedure FLAG_SET_ADDRSIZE(di: PDInst; size: UInt8);
  //#define FLAG_GET_OPSIZE(flags) (((flags) >> 8) & 3)
  function FLAG_GET_OPSIZE(flags: UInt16): UInt8;
  //#define FLAG_GET_ADDRSIZE(flags) (((flags) >> 10) & 3)
  function FLAG_GET_ADDRSIZE(flags: UInt16): UInt8;

  //* To get the LOCK/REPNZ/REP prefixes. */
  //#define FLAG_GET_PREFIX(flags) ((flags) & 7)
  function FLAG_GET_PREFIX(flags: UInt16): UInt8;
  //#define FLAG_GET_PRIVILEGED(flags) (((flags) & FLAG_PRIVILEGED_INSTRUCTION) != 0)
  function FLAG_GET_PRIVILEGED(flags: UInt16): Boolean;

// *
// * Macros to extract segment registers from 'segment':
// *

const
  SEGMENT_DEFAULT = $80;

  //#define SEGMENT_SET(di, seg) ((di->segment) |= seg)
  procedure SEGMENT_SET(di: PDInst; seg: UInt8);
  //#define SEGMENT_GET(segment) (((segment) == R_NONE) ? R_NONE : ((segment) & 0x7f))
  function SEGMENT_GET(segment: UInt8): UInt8;
  //#define SEGMENT_GET_UNSAFE(segment) ((segment) & 0x7f)
  function SEGMENT_GET_UNSAFE(segment: UInt8): UInt8;
  //#define SEGMENT_IS_DEFAULT(segment) (((int8_t)segment) < -1) /* Quick check it's a negative number that isn't -1, so it's (0x80 | SEGREG). */
  function SEGMENT_IS_DEFAULT(segment: UInt8): Boolean;
  //#define SEGMENT_IS_DEFAULT_OR_NONE(segment) (((uint8_t)(segment)) > 0x80)
  function SEGMENT_IS_DEFAULT_OR_NONE(segment: UInt8): Boolean;

// Static size of strings. Do not change this value. Keep Python wrapper in sync.
const
  MAX_TEXT_SIZE = 48;

type
  _WString = record
    length: UInt32;
    p: array [0..MAX_TEXT_SIZE - 1] of UChar; // p is a null terminated string.
  end;

type
{*
 * Old decoded instruction structure in text format.
 * Used only for backward compatibility with diStorm64.
 * This structure holds all information the disassembler generates per instruction.
 *}
 PDecodedInst = ^TDecodedInst;
  _DecodedInst = record
    offset: _OffsetType; // Start offset of the decoded instruction.
    size: UInt; // Size of decoded instruction in bytes.
    mnemonic: _WString; // Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc.
    operands: _WString; // Operands of the decoded instruction, up to 3 operands, comma-seperated.
    instructionHex: _WString; // Hex dump - little endian, including prefixes.
  end;
  TDecodedInst = _DecodedInst;

const
  // Register masks for quick look up, each mask indicates one of a register-class that is being used in some operand.
  RM_AX = 1;     //* AL, AH, AX, EAX, RAX */
  RM_CX = 2;     //* CL, CH, CX, ECX, RCX */
  RM_DX = 4;     //* DL, DH, DX, EDX, RDX */
  RM_BX = 8;     //* BL, BH, BX, EBX, RBX */
  RM_SP = $10;   //* SPL, SP, ESP, RSP */
  RM_BP = $20;   //* BPL, BP, EBP, RBP */
  RM_SI = $40;   //* SIL, SI, ESI, RSI */
  RM_DI = $80;   //* DIL, DI, EDI, RDI */
  RM_FPU = $100; //* ST(0) - ST(7) */
  RM_MMX = $200; //* MM0 - MM7 */
  RM_SSE = $400; //* XMM0 - XMM15 */
  RM_AVX = $800; //* YMM0 - YMM15 */
  RM_CR = $1000; //* CR0, CR2, CR3, CR4, CR8 */
  RM_DR = $2000; //* DR0, DR1, DR2, DR3, DR6, DR7 */
  RM_R8 = $4000; //* R8B, R8W, R8D, R8 */
  RM_R9 = $8000; //* R9B, R9W, R9D, R9 */
  RM_R10 = $10000; //* R10B, R10W, R10D, R10 */
  RM_R11 = $20000; //* R11B, R11W, R11D, R11 */
  RM_R12 = $40000; //* R12B, R12W, R12D, R12 */
  RM_R13 = $80000; //* R13B, R13W, R13D, R13 */
  RM_R14 = $100000; //* R14B, R14W, R14D, R14 */
  RM_R15 = $200000; //* R15B, R15W, R15D, R15 */
  RM_SEG = $400000; //* CS, SS, DS, ES, FS, GS */

{* RIP should be checked using the 'flags' field and FLAG_RIP_RELATIVE.
 * Segments should be checked using the segment macros.
 * For now R8 - R15 are not supported and non general purpose registers map into same RM.
 *}

// CPU flags that instructions modify, test or undefine (are EFLAGS compatible!).
  D_CF = 1;		//* Carry */
  D_PF = 4;		//* Parity */
  D_AF = $10;	//* Auxiliary */
  D_ZF = $40;	//* Zero */
  D_SF = $80;	//* Sign */
  D_IF = $200;	//* Interrupt */
  D_DF = $400;	//* Direction */
  D_OF = $800;	//* Overflow */

{*
 * Instructions Set classes:
 * if you want a better understanding of the available classes, look at disOps project, file: x86sets.py.
 *}
  // Indicates the instruction belongs to the General Integer set.
  ISC_INTEGER = 1;
  // Indicates the instruction belongs to the 387 FPU set.
  ISC_FPU = 2;
  // Indicates the instruction belongs to the P6 set.
  ISC_P6 = 3;
  // Indicates the instruction belongs to the MMX set.
  ISC_MMX = 4;
  // Indicates the instruction belongs to the SSE set.
  ISC_SSE = 5;
  // Indicates the instruction belongs to the SSE2 set.
  ISC_SSE2 = 6;
  // Indicates the instruction belongs to the SSE3 set.
  ISC_SSE3 = 7;
  // Indicates the instruction belongs to the SSSE3 set.
  ISC_SSSE3 = 8;
  // Indicates the instruction belongs to the SSE4.1 set.
  ISC_SSE4_1 = 9;
  // Indicates the instruction belongs to the SSE4.2 set.
  ISC_SSE4_2 = 10;
  // Indicates the instruction belongs to the AMD's SSE4.A set.
  ISC_SSE4_A = 11;
  // Indicates the instruction belongs to the 3DNow! set.
  ISC_3DNOW = 12;
  // Indicates the instruction belongs to the 3DNow! Extensions set.
  ISC_3DNOWEXT = 13;
  // Indicates the instruction belongs to the VMX (Intel) set.
  ISC_VMX = 14;
  // Indicates the instruction belongs to the SVM (AMD) set.
  ISC_SVM = 15;
  // Indicates the instruction belongs to the AVX (Intel) set.
  ISC_AVX = 16;
  // Indicates the instruction belongs to the FMA (Intel) set.
  ISC_FMA = 17;
  // Indicates the instruction belongs to the AES/AVX (Intel) set.
  ISC_AES = 18;
  // Indicates the instruction belongs to the CLMUL (Intel) set.
  ISC_CLMUL = 19;

  // Features for decompose:
  DF_NONE = 0;
  // The decoder will limit addresses to a maximum of 16 bits.
  DF_MAXIMUM_ADDR16 = 1;
  // The decoder will limit addresses to a maximum of 32 bits.
  DF_MAXIMUM_ADDR32 = 2;
  // The decoder will return only flow control instructions (and filter the others internally).
  DF_RETURN_FC_ONLY = 4;
  // The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded.
  DF_STOP_ON_CALL = 8;
  // The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded.
  DF_STOP_ON_RET = $10;
  // The decoder will stop and return to the caller when the instruction system-call/ret was decoded.
  DF_STOP_ON_SYS = $20;
  // The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions were decoded.
  DF_STOP_ON_UNC_BRANCH = $40;
  // The decoder will stop and return to the caller when any of the conditional branch instruction were decoded.
  DF_STOP_ON_CND_BRANCH = $80;
  // The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was decoded.
  DF_STOP_ON_INT = $100;
  // The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded.
  DF_STOP_ON_CMOV = $200;
  // The decoder will stop and return to the caller when it encounters the HLT instruction.
  DF_STOP_ON_HLT = $400;
  // The decoder will stop and return to the caller when it encounters a privileged instruction.
  DF_STOP_ON_PRIVILEGED = $800;
  // The decoder will stop and return to the caller when an instruction couldn't be decoded.
  DF_STOP_ON_UNDECODEABLE = $1000;
  // The decoder will not synchronize to the next byte after the previosuly decoded instruction, instead it will start decoding at the next byte.
  DF_SINGLE_BYTE_STEP = $2000;
  // The decoder will fill in the eflags fields for the decoded instruction.
  DF_FILL_EFLAGS = $4000;
  // The decoder will use the addrMask in CodeInfo structure instead of DF_MAXIMUM_ADDR16/32.
  DF_USE_ADDR_MASK = $8000;
  // The decoder will stop and return to the caller when any flow control instruction was decoded.
  DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL or DF_STOP_ON_RET or
    DF_STOP_ON_SYS or DF_STOP_ON_UNC_BRANCH or DF_STOP_ON_CND_BRANCH or
    DF_STOP_ON_INT or DF_STOP_ON_CMOV or DF_STOP_ON_HLT);

  // Indicates the instruction is not a flow-control instruction.
  FC_NONE = 0;
  // Indicates the instruction is one of: CALL, CALL FAR.
  FC_CALL = 1;
  // Indicates the instruction is one of: RET, IRET, RETF.
  FC_RET = 2;
  // Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
  FC_SYS = 3;
  // Indicates the instruction is one of: JMP, JMP FAR.
  FC_UNC_BRANCH = 4;
{*
 * Indicates the instruction is one of:
 * JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
 *}
  FC_CND_BRANCH = 5;
  // Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
  FC_INT = 6;
  // Indicates the instruction is one of: CMOVxx.
  FC_CMOV = 7;
  //Indicates the instruction is HLT.
  FC_HLT = 8;

type
  // Return code of the decoding function.
  TDecodeResult = (DECRES_NONE, DECRES_SUCCESS, DECRES_MEMORYERR, DECRES_INPUTERR, DECRES_FILTERED);

{* distorm_decode
 * Input:
 *         offset - Origin of the given code (virtual address that is), NOT an offset in code.
 *         code - Pointer to the code buffer to be disassembled.
 *         length - Amount of bytes that should be decoded from the code buffer.
 *         dt - Decoding mode, 16 bits (Decode16Bits), 32 bits (Decode32Bits) or AMD64 (Decode64Bits).
 *         result - Array of type _DecodeInst which will be used by this function in order to return the disassembled instructions.
 *         maxInstructions - The maximum number of entries in the result array that you pass to this function, so it won't exceed its bound.
 *         usedInstructionsCount - Number of the instruction that successfully were disassembled and written to the result array.
 * Output: usedInstructionsCount will hold the number of entries used in the result array
 *         and the result array itself will be filled with the disassembled instructions.
 * Return: DECRES_SUCCESS on success (no more to disassemble), DECRES_INPUTERR on input error (null code buffer, invalid decoding mode, etc...),
 *         DECRES_MEMORYERR when there are not enough entries to use in the result array, BUT YOU STILL have to check for usedInstructionsCount!
 * Side-Effects: Even if the return code is DECRES_MEMORYERR, there might STILL be data in the
 *               array you passed, this function will try to use as much entries as possible!
 * Notes:  1)The minimal size of maxInstructions is 15.
 *         2)You will have to synchronize the offset,code and length by yourself if you pass code fragments and not a complete code block!
 *}

  function distorm_decode(
    codeOffset: _OffsetType; code: Pointer; codeLen: Integer; dt: _DecodeType;
    AResult: PDecodedInst; maxInstructions: UInt;
    usedInstructionsCount: PUInt): TDecodeResult;

  procedure distorm_format(ci: PCodeInfo; di: PDInst; AResult: PDecodedInst);

{* distorm_decompose
 * There is lots of documentation about diStorm at https://github.com/gdabah/distorm/wiki
 *
 * Please read https://github.com/gdabah/distorm/wiki/DecomposeInterface
 *
 * And also see https://github.com/gdabah/distorm/wiki/TipsnTricks
 *
 *}

  function distorm_decompose(
    ci: PCodeInfo; AResult: PDInst;
    maxInstructions: UInt; usedInstructionsCount: PUInt): TDecodeResult;

  function get_distorm_version: Cardinal;

implementation

// Macros
// =============================================================================

function META_GET_ISC(meta: UInt16): UInt8;
begin
  Result := (meta shr 8) and $1F;
end;

procedure META_SET_ISC(di: PDInst; isc: UInt8);
begin
  di^.meta := di^.meta or (isc shl 8);
end;

function META_GET_FC(meta: UInt16): UInt8;
begin
  Result := meta and $F;
end;

function INSTRUCTION_GET_TARGET(di: PDInst): _OffsetType;
begin
  Result := di^.addr + di^.imm.addr + di^.size;
end;

function INSTRUCTION_GET_RIP_TARGET(di: PDInst): _OffsetType;
begin
  Result := di^.addr + di^.disp + di^.size;
end;

procedure FLAG_SET_OPSIZE(di: PDInst; size: UInt8);
begin
  di.flags := di.flags or ((size and 3) shl 8);
end;

procedure FLAG_SET_ADDRSIZE(di: PDInst; size: UInt8);
begin
  di.flags := di.flags or ((size and 3) shl 10);
end;

function FLAG_GET_OPSIZE(flags: UInt16): UInt8;
begin
  Result := (flags shr 8) and 3;
end;

function FLAG_GET_ADDRSIZE(flags: UInt16): UInt8;
begin
  Result := (flags shr 10) and 3;
end;

function FLAG_GET_PREFIX(flags: UInt16): UInt8;
begin
  Result := flags and 7;
end;

function FLAG_GET_PRIVILEGED(flags: UInt16): Boolean;
begin
  Result := (flags and FLAG_PRIVILEGED_INSTRUCTION) <> 0;
end;

procedure SEGMENT_SET(di: PDInst; seg: UInt8);
begin
  di^.segment := di^.segment or seg;
end;

function SEGMENT_GET(segment: UInt8): UInt8;
begin
  if segment = R_NONE then
    Result := R_NONE
  else
    Result := segment and $7F;
end;

function SEGMENT_GET_UNSAFE(segment: UInt8): UInt8;
begin
  Result := segment and $7F;
end;

function SEGMENT_IS_DEFAULT(segment: UInt8): Boolean;
begin
  Result := Int8(segment) < -1;
end;

function SEGMENT_IS_DEFAULT_OR_NONE(segment: UInt8): Boolean;
begin
  Result := UInt8(segment) > $80;
end;

//  Strap for OBJ files
// =============================================================================

procedure _memset(pBuff: PByte; c: Integer; nCount: Integer); cdecl;
begin
  ZeroMemory(pBuff, nCount);
end;

procedure __aullshr;
asm
        cmp     cl,64
        jae     @RETZERO
        cmp     cl, 32
        jae     @MORE32
        shrd    eax,edx,cl
        shr     edx,cl
        ret
@MORE32:
        mov     eax,edx
        xor     edx,edx
        and     cl,31
        shr     eax,cl
        ret
@RETZERO:
        xor     eax,eax
        xor     edx,edx
        ret
end;

{$IFDEF WIN32}
  procedure _FlagsTable; external;
  procedure _InstSharedInfoTable; external;
  procedure _CmpMnemonicOffsets; external;
  procedure _VCmpMnemonicOffsets; external;
  procedure _decode_internal; external;
  procedure _InstInfos; external;
  procedure _InstInfosEx; external;
  procedure _InstructionsTree; external;
  procedure __MNEMONICS; external;
  procedure __REGISTERS; external;
  procedure _Table_0F_0F; external;
  procedure _Table_0F; external;
  procedure _Table_0F_38; external;
  procedure _Table_0F_3A; external;
  procedure _II_MOVSXD; external;
  procedure _II_NOP; external;
  procedure _II_PAUSE; external;
  procedure _II_RDRAND; external;
  procedure _II_3DNOW; external;
  function _distorm_version: Cardinal; external;
{$ELSE}
  procedure FlagsTable; external;
  procedure InstSharedInfoTable; external;
  procedure CmpMnemonicOffsets; external;
  procedure VCmpMnemonicOffsets; external;
  procedure decode_internal; external;
  procedure InstInfos; external;
  procedure InstInfosEx; external;
  procedure InstructionsTree; external;
  procedure _MNEMONICS; external;
  procedure _REGISTERS; external;
  procedure Table_0F_0F; external;
  procedure Table_0F; external;
  procedure Table_0F_38; external;
  procedure Table_0F_3A; external;
  procedure II_MOVSXD; external;
  procedure II_NOP; external;
  procedure II_PAUSE; external;
  procedure II_RDRAND; external;
  procedure II_3DNOW; external;
  function distorm_version: Cardinal; external;
{$ENDIF}

  function {$IFDEF WIN32}_distorm_decode64{$ELSE}distorm_decode64{$ENDIF}
    (codeOffset: _OffsetType; code: Pointer; codeLen: Integer; dt: Cardinal; // _DecodeType;
    AResult: PDecodedInst; maxInstructions: UInt;
    usedInstructionsCount: PUInt): TDecodeResult; cdecl; external;

  procedure {$IFDEF WIN32}_distorm_format64{$ELSE}distorm_format64{$ENDIF}
    (ci: PCodeInfo; di: PDInst; AResult: PDecodedInst); cdecl; external;

  function {$IFDEF WIN32}_distorm_decompose64{$ELSE}distorm_decompose64{$ENDIF}
    (ci: PCodeInfo; AResult: PDInst;
    maxInstructions: UInt; usedInstructionsCount: PUInt): TDecodeResult;
    cdecl; external;

// = decorators ================================================================

function distorm_decode(codeOffset: _OffsetType; code: Pointer;
  codeLen: Integer; dt: _DecodeType; AResult: PDecodedInst;
  maxInstructions: UInt; usedInstructionsCount: PUInt): TDecodeResult;
begin
  Result := {$IFDEF WIN32}_distorm_decode64{$ELSE}distorm_decode64{$ENDIF}(
    codeOffset, code, codeLen,
    Cardinal(dt), AResult, maxInstructions, usedInstructionsCount);
end;

procedure distorm_format(ci: PCodeInfo; di: PDInst; AResult: PDecodedInst);
begin
  {$IFDEF WIN32}_distorm_format64{$ELSE}distorm_format64{$ENDIF}(
    ci, di, AResult);
end;

function distorm_decompose(ci: PCodeInfo; AResult: PDInst;
  maxInstructions: UInt; usedInstructionsCount: PUInt): TDecodeResult;
begin
  Result := {$IFDEF WIN32}_distorm_decompose64{$ELSE}distorm_decompose64{$ENDIF}(
    ci, AResult, maxInstructions, usedInstructionsCount);
end;

function get_distorm_version: Cardinal;
begin
  {$IFDEF WIN32}
  Result := _distorm_version;
  {$ELSE}
  Result := distorm_version;
  {$ENDIF}
end;

end.
