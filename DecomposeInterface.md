In this page I'm going to cover how to parse the Decompose output.

The _DInst structure is very compact, is it designed to be as minimal as possible, knowing that diStorm is aimed for x86 and AMD64 helped in saving memory space._

<i>A few <b>must-follow</b> rules for using the Decompose interface:</i>
  1. Always check that the returned instruction is valid first! Do that by comparing the 'flags' field to FLAG\_NOT\_DECODABLE.
  1. Access only fields that you know you are allowed to by the type of the operands. In the explanation below, every field indicates when it's set. Some fields are always set, and some are dependent on other fields.
  1. Always use the helper macros that are described along this page, in the future I might change some bits and bytes and it will break your software.
  1. The last rule applies to macros that define values too rather than only 'functionality', like R\_NONE. Always check that a register index is set, by comparing it to R\_NONE. (For instance, if you compare it yourself to -1, you might get bogus results because of integer promotions).

Again, the following structure was designed specially for the x86 and AMD64 architectures, that's why some fields are global to the instruction although a more appropriate place for them should be inside the Operand structure. This is in order to spare bytes. For example, there's no reason to have an 'immediate' field in every operand, because the x86 defines that an instruction can have at most 1 immediate operand. (This is true except the ENTER instruction, you will find more information below about it).

If you wish to get the textual representation of either a register or an instruction. You should include 'mnemonics.h' in your project. And use GET\_REGISTER\_NAME to get the string for a given register index.
Also, in the 'mnemonics.h' you will find other enum's that will aid your parsing, like all supported registers (R\_EAX, R\_DS, R\_CR0, etc) and opcodes (I\_MOV, I\_ADD, I\_CALL), etc.

If you wish to convert the _DInst structure, that you got as a result from the Decompose function, into text, there's a new function that does just that, distorm\_format. It requires the result and the_<i>old</i> structure _DecodedInst which will hold the textual representation of the instruction, including prefixes. This will save you the hassle from converting the operands into text and taking care of the prefixes and other subtle issues. You should use the distorm\_format, rather than calling distorm\_decode on the same instruction, because it does what it name suggests, just formats the instruction as text._

### struct _DInst: ###_

<b>_OffsetType addr;</b>
  * Always set.
  * The virtual address of the instruction.
  * It is determined according to the given start address of the call to the Decompose function._

<b>uint8_t size;</b>
  * Always set.
  * The size of the whole instruction. Varying from 1 to 15 bytes long.

<b>uint16_t flags;</b>
  * Always set.
  * Very important to check this field before touching the other fields.
  * If it's set to FLAG\_NOT\_DECODABLE, the instruction is invalid.
  * See [DecomposeInterface#Flags](DecomposeInterface#Flags.md) for more information.

<b>uint8_t segment;</b>
  * Set when one of the operands is of type O\_SMEM, O\_MEM, O\_DISP.
  * Helper macros: SEGMENT\_GET, SEGMENT\_IS\_DEFAULT.
  * SEGMENT\_IS\_DEFAULT returns TRUE if the segment register is the default one for the operand. For instance: `MOV [EBP], AL` - the default segment register is SS. However, `MOV [FS:EAX], AL` - The default segment is DS, but we overrode it with FS, therefore the macro will return FALSE.
  * To extract the segment register index use the SEGMENT\_GET macro.
  * R\_NONE if not set.

<b>uint8_t base;</b>
  * Set when one of the operands is of type O\_MEM.
  * It is the register index of the Base. I.E: `MOV [EAX+EBX*4], EDI` - it is R\_EAX.
  * R\_NONE if not set.

<b>uint8_t scale;</b>
  * Set when one of the operands is of type O\_MEM.
  * The Scale is a pair to the Index register in a memory indirection operand, which is described in the Operand structure.
  * The scale can be either 0, 1, 2, 4, 8. If it's not set it is 0.

<b>uint8_t dispSize;</b>
  * Set when one of the operands is of type O\_SMEM, O\_MEM, O\_DISP and the instruction has a displacement.
  * This is the size of the 'disp' field in bits.
  * If there's no displacement set, this field is 0.

<b>uint16_t opcode;</b>
  * Always set.
  * If the instruction is invalid it is set to I\_UNDEFINED.
  * Include the file "mnemonics.h" to use the Instructions-Enum.
  * An helper macro to get the textual representation for an instruction is GET\_MNEMONIC\_NAME.
  * For instance, if you want to check that a decomposed instruction is 'POP', then compare this field to I\_POP. Basically add a prefix of "I_" to the upcased name of the instruction you want to check. You can see the whole list in the "mnemonics.h" file._

<b><code>_Operand ops[OPERANDS_NO];</code></b>
  * An array of 4 _Operand's.
  * However, they might be empty.
  * See [DecomposeInterface#Operands](DecomposeInterface#Operands.md) for more information._

<b>uint64_t disp;</b>
  * Set when one of the operands is of type O\_SMEM, O\_MEM, O\_DISP and the instruction has a displacement.
  * The only way to know that an instruction as a displacement is to check that dispSize != 0.
  * Some instructions use a displacement of 0. I.E: `MOV [EBP], EAX`.

<b>_Value imm;</b>
  * Set when one of the operands is of type O\_IMM, O\_IMM1&O\_IMM2, O\_PTR, O\_PC.
  * The size of the immediate value itself is the Operand.size field.
  * See [DecomposeInterface#Immediate](DecomposeInterface#Immediate.md) for more information._

<b>uint16_t unusedPrefixesMask;</b>
  * Always set.
  * This field indicates which of the prefixes of the instruction were unused.
  * There are two reasons as for why a prefix is unused, either because it didn't affect the decoding of the instruction. I.E: db 0x66; ADD AL, 1. The 0x66 (Operand Size) prefix doesn't affect the instruction in this case and therefore is unused. The other reason is when there are more than one prefix of the same type (see x86 documentation). I.E: db 0x2e, db 0x3e, MOV [EAX](EAX.md), AL. We tried to set a segment override twice, so only the last one (0x3e) is taken into account, the first one is unused.
  * Normally instructions **should not** have unused prefixes. It might mean that you disassemble invalid code (or data). Or it might mean you disassemble an aligning instruction such as: 0x66, 0x66, 0x90 to fill in a space of 3 bytes to round up to next multiple of 8/16, etc.
  * A quick check to see if the instruction has unused prefixes is 'unusedPrefixesMask != 0'.
  * So which prefixes are unused really? Since this field is a mask, the first bit denotes the first byte of the instruction, and so on, starting at 'addr' field. Basically use the following code:
```
for (int i = 0; i < sizeof(uint16_t); i++) {
 if (DecomposedInst.unusedPrefixesMask & (1 << i))
  printf("Unused prefix %02x at offset: %x\n", CodeBuffer[DecomposedInst.addr - StartCodeOffset + i], DecomposedInst.addr + i); 
}
```

<b>uint8_t meta;</b>
  * Always set.
  * This field holds meta information to the instruction.
  * It contains two sub-fields which should be extracted using the helper macros: META\_GET\_ISC, META\_GET\_FC.
  * META\_GET\_ISC returns the Instruction-Set-Class type of the instruction. I.E: ISC\_INTEGER, ISC\_FPU, and many more. See distorm.h for the complete list.
  * META\_GET\_FC returns the Flow-Control type of the instruction. I.E: FC\_CALL, FC\_BRANCH and others. Usually it's FC\_NONE. See the rest of them inside distorm.h.
  * The meta-FC is very useful for flow control analysis.

<b>uint16_t usedRegistersMask;</b>
  * Set when the instruction is valid and uses registers in its operands.
  * This field is actually a <b>mask</b> for all the registers that are used in the operands.
  * Practically, instead of scanning for a specific register in the operands, you should use this field.
  * This field is not a replacement to the operands information! It is just a hint, hence a mask.
  * The registers are categorized to register-classes such as:

| AL, AH, AX, EAX, RAX | RM\_AX |
|:---------------------|:-------|
| CL, CH, CX, ECX, RCX | RM\_CX |
| DL, DH, DX, EDX, RDX | RM\_DX |
| BL, BH, BX, EBX, RBX | RM\_BX |
| SPL, SP, ESP, RSP | RM\_SP |
| BPL, BP, EBP, RBP | RM\_BP |
| SIL, SI, ESI, RSI | RM\_SI |
| DIL, DI, EDI, RDI | RM\_DI |
| ST(0) - ST(7) | RM\_FPU |
| MM0 - MM7 | RM\_MMX |
| XMM0 - XMM15 | RM\_SSE |
| YMM0 - YMM15 | RM\_AVX |
| CR0, CR2, CR3, CR4, CR8 | RM\_CR |
| DR0, DR1, DR2, DR3, DR6, DR7 | RM\_DR |

Note that RIP can be checked with the FLAG\_RIP\_RELATIVE. Segment registers have the 'segment' field. And [R8](https://code.google.com/p/distorm/source/detail?r=8)-[R15](https://code.google.com/p/distorm/source/detail?r=15) are not mapped, I might add them in the future.



The following three fields describe how the instruction affects the CPU flags.
It's a simple bit mask that can be tested using the following values:
|D\_ZF | Zero Flag |
|:-----|:----------|
|D\_SF | Sign Flag |
|D\_CF | Carry Flag |
|D\_OF | Overflow Flag |
|D\_PF | Parity Flag |
|D\_AF | Auxiliary Flag |
|D\_DF | Direction Flag |
|D\_IF | Interrupt Flag |

<b>uint8_t modifiedFlags;</b>
  * Use the above flags to check if a specific CPU flag is being modified (output) by this instruction.

<b>uint8_t testedFlags;</b>
  * Use the above flags to check if a specific CPU flag is being tested (input) by this instruction.

<b>uint8_t undefinedFlags;</b>
  * Use the above flags to check if a specific CPU flag is being undefined (output) by this instruction.


---


### Flags ###
The 'flags' field has a few more options, they are pretty advanced though, but nothing special.
Use the helper macros: FLAG\_GET\_OPSIZE, FLAG\_GET\_ADDRSIZE, FLAG\_GET\_PREFIX.
FLAG\_GET\_OPSIZE returns the DecodeType (Decode16Bits, Decode32Bits or Decode64Bits) of the operand, thus it's the size of the operand.

FLAG\_GET\_ADRSIZE returns the DecodeType (Decode16Bits, Decode32Bits or Decode64Bits) of the operand, thus it's the size of the referenced memory by the operand.

It is important to understand the meaning of the two sizes:
`MOV EAX, EBX` - operand size is 32 in both operands.
`MOV [EAX], byte ptr 0` - operand size is 8 in both operands, however the size of the register that references the memory, EAX, is obviously 32 (or Decode32Bits).
And one more thing about it, it's the effective operand/address size, rather than the input DecodeType you supply when calling the Decompose function (this can happen with prefixes for the instruction)!

FLAG\_GET\_PREFIX returns the prefix of the instruction (FLAG\_LOCK, FLAG\_REPNZ, FLAG\_REP). Note that the string instructions CMPS and SCAS treats the FLAG\_REP as 'REPZ'.

There are a few more flags such as:
FLAG\_HINT\_TAKEN, FLAG\_HINT\_NOT\_TAKEN, FLAG\_IMM\_SIGNED.
You can check for these flags by doing: if ((DecomposedInst.flags & FLAG\_XXX) != 0)
The first two are pretty self-explanatory, if you know what they mean :)
The FLAG\_IMM\_SIGNED is important if you want to know whether to treat the immediate as a signed or unsigned integer (some instructions supply this information).

FLAG\_DST\_WR - This flag indicates whether the first operand, that is the destination operand, is writable or not. This way you can know dependency between instructions. For example: MOV EBX, EAX -> EBX gets overridden, hence the flag will be set. But for: PUSH EBX, the flag is not set, since the PUSH instruction doesn't write to the EBX register. Note that this flag is only supported in Integer instructions.

FLAG\_RIP\_RELATIVE indicates when an instruction in 64 bits uses the RIP-relative memory indirection addressing. In order to get the absolute target address you can use the INSTRUCTION\_GET\_RIP\_TARGET. This flag will spare you the scanning for the RIP register in the operands.

And last but not least, FLAG\_PRIVILEGED\_INSTRUCTION indicates that the instruction is a privileged instruction, one that can run only from ring 0.

### Operands ###
> As we said earlier, the 'operands' field is an array of 4 operand structures. This is probably the most important information you would want to extract from an instruction.

An operand is defined as:
```
typedef struct {
	/* Type of operand:
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
	*/
	uint8_t type; /* _OperandType */

	/* Index of:
	O_REG: holds global register index
	O_SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
	O_MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
	*/
	uint8_t index;

	/* Size in bits of:
	O_REG: register
	O_IMM: instruction.imm
	O_IMM1: instruction.imm.ex.i1
	O_IMM2: instruction.imm.ex.i2
	O_DISP: instruction.disp
	O_SMEM: size of indirection.
	O_MEM: size of indirection.
	O_PC: size of the relative offset
	O_PTR: size of instruction.imm.ptr.off (16 or 32)
	*/
	uint16_t size;
} _Operand;
```

That's pretty self-explanatory I would say.
I just wanted to note that I decided to have both O\_SMEM and O\_MEM separated. Since most of the times instructions have, what I call, simple memory dereference, so only one register, and you get its index in the operand.index already. The thing is, when you encounter O\_MEM, it really means you are going to have two registers in the operand.

About the operand.size field, it describes the size of the object that the operand represents, it can be the size of the register if the type is O\_REG. Or it can be the size of the memory dereference. I.E: `MOV [BX], EAX` - The destination is size is 32 bits. But the size of the register is 16 bits, though in such a case the size of the index is not specified and you should know it because you have the index of the register which says, R\_BX. So practically, the size of the register when the type is O\_REG is a bonus, because we just realized we can get this information by the index of the register.

I hope it is clear that the order of operands is based on the order of this array.
If the operand.type is O\_NONE you can stop querying the operands in the array.

### Immediate ###
The 'immediate' field should be treated very carefully. If you take a closer look, you will notice it is defined as a _Value type, which defined as:
```
typedef union {
	/* Used by O_IMM: */
	int8_t sbyte;
	uint8_t byte;
	int16_t sword;
	uint16_t word;
	int32_t sdword;
	uint32_t dword;
	int64_t sqword; /* All immediates are SIGN-EXTENDED to 64 bits! */
	uint64_t qword;

	/* Used by O_PC: */
	_OffsetType addr;

	/* Used by O_PTR: */
	struct {
		uint16_t seg;
		/* Can be 16 or 32 bits, size is in ops[n].size. */
		uint32_t off;
	} ptr;

	/* Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only. */
	struct {
		uint32_t i1;
		uint32_t i2;
	} ex;
} _Value;
```_

**Important note:**
As you can see, if the operand type is **O\_IMM**, you can get the immediate value from the sbyte, byte, ..., sqword, qword. On first glance it looks intimidating. Let me explain, in most cases you want and should use the qword or sqword parts of the union. diStorm already **signed extends** the immediates to the size of 64 bits types. So stick to them, it will be much easier for you.
Although, you can happily use the other union-fields for accessing the same immediate, if that suits, go ahead. That's why you have the size of the immediate stored in the operand.size field.

Now let's talk about the ENTER instruction, it's the only instruction so far that has **two** immediates. Now, we surely don't want to allocate a whole _Value structure for a rare used instruction. And besides since the sizeof(_Value) is 8 bytes, we can surely squeeze in a 16 bits and 8 bits immeidates inside, and that's why I added the sub-structure 'ex'.
So if you encounter an operand type of O\_IMM1, it means you should read the immediate from 'imm.ex.i1', and 'imm.ex.i2' for O\_IMM2.

The O\_PTR type is found only in instruction that access <i>far</i> memory, such as: JMP FAR, CALL FAR, etc. So to get both the segment/selector and the offset use 'imm.ptr.seg' and 'imm.ptr.off'.

The O\_PC type is found in branching instruction such as: JNZ, JB, JMP, CALL, etc. The value stored in the union is really the **relative offset** from the current instruction. Therefore if you want to calculate the **target** address of the branch, use the helper macro INSTRUCTION\_GET\_TARGET. In order to access the relative part solely, use 'imm.addr'. The size of the relative value is operand.size field.
Note: in the past, before diStorm3 was official, the 'imm.addr' used to be the absolute target address, I might revert it in the future. And unfortunately, I can't recall why I did this change.


---

Now that you read everything, you should take a look at [Showcases](Showcases.md) and you will understand what's going on. You're ready to go, good luck.

---

Also a good example of how to use the Decompose API can be found at (look for the distorm\_decompose function):
http://code.google.com/p/distorm/source/browse/trunk/src/distorm.c