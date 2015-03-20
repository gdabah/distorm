<pre>
/--------------\<br>
|Decoding Modes|<br>
\--------------/<br>
Decoding mode specifies the default size of an operation.<br>
A code block is constructed from a sequence of instructions.<br>
The decoding mode tells how that code(-the instructions) is being processed.<br>
They can be processed in 16, 32 or 64 bits.<br>
The number of bits is the operation size of each instruction.<br>
DOS is known to be a 16 bits OS, thus the CPU executes its code in a 16 bits environment.<br>
Windows and Linux are 32 bits, and even 64 bits nowadays...<br>
Every piece of code or an instruction has to be disassembled in the corresponding size it was assembled/compiled to.<br>
The disassembler disassembles the instructions according to this decoding mode only,<br>
it makes much sense, because every decode mode supports different instruction sets or instructions and<br>
can do different operations, so you have to know in advance the decoding mode of the stream you want to disassemble.<br>
<br>
The 3 modes supported by diStorm are:<br>
16 bits (Decode16Bits) - Instruction sets supported: 80186/80286<br>
32 (Decode32Bits) - Instruction sets supported: 80x86 (Not including x64)<br>
AMD64 (Decode64Bits) - Instruction sets supported: 80x86 + x64 (Not including prohibited instructions)<br>
<br>
In addition to these instruction sets, there are more instruction sets that are supported no matter the mode,<br>
these are the FPU, SSE, SSE2, SSE3, 3DNow!, 3DNow! extensions (and some P6 instructions), VMX and SSSE3 instructions.<br>
Maybe the 16 bits decoding mode doesn't necessarily require all these sets,<br>
but I found it useful, it can't harm nobody, anyways...<br>
<br>
Every decode mode has a default operand size and address size, more on this later.<br>
<br>
/-----------------\<br>
|80x86 Instruction|<br>
\-----------------/<br>
A 80x86 instruction is divided to a number of elements:<br>
1)Instruction prefixes, affects the behaviour of the instruction's operation.<br>
2)Mandatory prefix used as an opcode byte for SSE instructions.<br>
3)Opcode bytes, could be one or more bytes (up to 3 whole bytes).<br>
4)ModR/M byte is optional and sometimes could contain a part of the opcode itself.<br>
5)SIB byte is optional and represents complex memory indirection forms.<br>
6)Displacement is optional and it is a value of a varying size of bytes(byte, word, long) and used as an offset.<br>
7)Immediate is optional and it is used as a general number value built from a varying size of bytes(byte, word, long).<br>
<br>
The format looks as follows:<br>
<br>
/-------------------------------------------------------------------------------------------------------------------------------------------\<br>
|*Prefixes | *Mandatory Prefix | *REX Prefix | <b>Opcode Bytes<br>
<br>
Unknown end tag for </b><br>
<br>
 | *ModR/M | *SIB | *Displacement (1,2 or 4 bytes) | *Immediate (1,2 or 4 bytes) |<br>
\-------------------------------------------------------------------------------------------------------------------------------------------/<br>
* means the element is optional.<br>
<br>
/--------------------\<br>
|Instruction Prefixes|<br>
\--------------------/<br>
The instruction prefixes are optional, they are used when the default behaviour of the instruction lacks functioning.<br>
If you want to extend the behaviour of the instruction, or change its parameters, prefixes might achieve your goal.<br>
There are 4 types of prefixes:<br>
Lock and Repeat<br>
Segment Override<br>
Operand Size<br>
Address Size<br>
<br>
The following table shows the value in hex of the prefix and its mnemonic:<br>
- Lock and Repeat:<br>
- 0xF0 — LOCK<br>
- 0xF2 — REPNE/REPNZ<br>
- 0xF3 - REP/REPE/REPZ<br>
- Segment Override:<br>
- 0x2E - CS<br>
- 0x36 - SS<br>
- 0x3E - DS<br>
- 0x26 - ES<br>
- 0x64 - FS<br>
- 0x65 - GS<br>
- Operand-Size Override: 0x66, switching to non-default size.<br>
- Address-Size Override: 0x67, switching to non-default size.<br>
<br>
Every instruction could have up to 4 prefixes and each prefix mustn't be used twice,<br>
otherwise it could lead to undefined behaviour by the processor.<br>
<br>
<i>Lock<br>
<br>
Unknown end tag for </i><br>
<br>
 prefix is used in order to lock the bus for writing.<br>
It is used for spin locks and other techniques for the sake of code synchornization.<br>
There is a small set of instructions which support the Lock prefix and that's also when the first operand is used as a memory indirection.<br>
If this prefix is used for an instruction which doesn't support it or the first operand isn't a memory indirection form, an exception is<br>
raised by the processor. In the case of the disassembler this prefix will be dropped (simply ignored).<br>
<br>
There is a hack in the IA-32 processors to access CR8 register, using the Lock prefix for mov cr(n) instruction it acts<br>
as the fourth (upper) bit of the REG field, this allows the processor reaching to the 8 upper CR registers.<br>
<br>
The disassembler first makes sure the instruction is lockable and if so it validates that the destination operand is in the memory indirection form.<br>
If these conditions aren't met, the prefix will be dropped.<br>
<br>
<i>Repeat<br>
<br>
Unknown end tag for </i><br>
<br>
 prefixes are considered to be the same type of the Lock prefix, so an instruction could only have Lock or Repeat, not both at the same time.<br>
Note that the disassembler is based on Intel's reference in this part of the code.<br>
The AMD reference seperates the LOCK and the Repeat prefixes as two different types.<br>
Repeat prefixes are used only with string instructions which support this prefix.<br>
The disassembler ignores this prefix if used for other instructions, thus ending up with this prefix dropped.<br>
There are two repeat prefixes, REPZ and REPNZ, repeat as long as the Zero flag (and rCX!=0) isn't set and vice versa.<br>
<br>
Side note:<br>
The meaning of rCX is a general-purpose register which can be one of the following: CX, ECX or RCX.<br>
Notice the small letter 'r', which says it's one of the CX registers...The names of the register indicates its size,<br>
which is defined according to the decoding mode.<br>
<br>
Note that repeat prefix can be used as a mandatory prefix for SSE instructions.<br>
<br>
The Repeat prefixes are treated specially with string instructions and when more prefixes are set.<br>
It could change the textual representation of the instruction in some cases.<br>
The way it's done in the disassembler is the same for all string instructions and is covered below.<br>
One more thing to say about repeat prefixes is that IO string instructions also support this (such as: ins, outs).<br>
<br>
<i>Segment Override<br>
<br>
Unknown end tag for </i><br>
<br>
 prefix is used in order to change the default segment for the instruction.<br>
Every general-purpose register has its default segment. For example SS for ESP, DS for BX, etc...<br>
If the instruction uses the memory indirection form and there is a segment override prefix set,<br>
then it will be displayed in front of the operand. If the instruction doesn't support operands,<br>
or in case the operands aren't in the memory indirection form, the prefix is dropped.<br>
In 64 bits decoding mode the CS, SS, DS and ES segment overrides are ignored and ineffective.<br>
<br>
<i>Operand Size<br>
<br>
Unknown end tag for </i><br>
<br>
 prefix is responsible for switching the operation size from the default size<br>
(depends on the instruction and decoding mode) to the non-default mode.<br>
It means that if the code is being run on a 32bits environment and the operand size prefix is used,<br>
that specific prefixed instruction will be run as a 16bits instruction.<br>
<br>
It is wrong to think that XOR EAX, EAX is different from XOR AX, AX - in their opcodes.<br>
Both instructions have the same bytes. There are only two options for representing them these ways.<br>
As stated earlier, most of the instructions are dependant on the decoding mode (16, 32).<br>
So if you decode that XOR in 16 bits, you will end up with XOR AX, AX,<br>
but if you decode that XOR in 32 bits, you will end up with XOR EAX, EAX.<br>
The operand size prefix comes into play when you want to change the operation size of the instruction,<br>
instead of the default size which is set by the decoding mode, to the non-default size.<br>
If you decode the XOR instruction in 16 bits, but prefix it with operand size prefix, it will result in XOR EAX, EAX.<br>
<br>
A known usage for operand size prefix in DOS (that is 16 bits code) was to fill the VGA screen using:<br>
db 0x66<br>
rep stosw<br>
which actually run as:<br>
rep stosd<br>
<br>
Note that operand size prefix can be used as a mandatory prefix for SSE instructions.<br>
<br>
<i>Address Size<br>
<br>
Unknown end tag for </i><br>
<br>
 prefix is quiet the same as Operand Size prefix, but acts on the memory indirection form of the operand.<br>
It switches the memory indirection form to the non-default form.<br>
Thus, if you read (in 16 bits) from [BP+DI], when prefixing it, the result is reading from [EBX].<br>
(This is right, because 16 bits has a different memory indirections tables from 32 bits).<br>
<br>
If you still ask yourself why you need both address and operand prefixes, the answer is right here.<br>
Let's do some order in the mess:<br>
You have to distinguish between the operand size and the address size.<br>
The operand size acts on OPERATION size. The operation size is determined implicitly by the instruction.<br>
For example (The default decoding mode is 16 bits):<br>
MOV AX, BX --> we know the operation size is 16 bits, because we know that AX and BX are 16 bits registers.<br>
MOV EAX, EBX --> 32 bits.<br>
MOV EAX, [EBX] --> still easy, EAX is 32 bits, so we read 32 bits from the memory.<br>
But what about this one:<br>
MOV [EBX], 5 --> You see the problem, you don't know the operation size, it might be that we write only one byte, or maybe two or at last, four.<br>
That's why in this case we have to explicitly tell the assembler, or display as the disassembler the operation size.<br>
<br>
The confusion still exists.<br>
MOV [BP+DI], DX --> 16 bits operation size.<br>
<br>
MOV [EBX], DX<br>
Now what!? No operand size is able to change BX into EBX in this case.<br>
An operand size prefix won't affect the memory indirection form!<br>
However, an address size prefix will affect it, thus changing BP+DI to EBX.<br>
Even so, when the address size prefix is set, the operation size is untouched and stays the same one, the default one.<br>
<br>
It is given that we decode in 16 bits in the following example:<br>
MOV [BP+DI], AX --> Nothing special<br>
MOV [EBX], AX --> This is done by Address Size prefix only.<br>
MOV [BP+DI], EAX --> This is done by Operand Size prefix only.<br>
MOV [EBX], EAX --> This is done by both address and operand size prefixes.<br>
<br>
In the bottom line, the address size prefix affects the operand only if it's in the memory indirection form, otherwise it's ignored.<br>
And the operand size affects the operation size, no matter in what form it is. It changes the amount of bytes the instruction is to work upon.<br>
Of course, there are instructions which have a fixed operation size, thus the operand size prefix is ignored/dropped.<br>
<br>
The behaviour of the operand/address size is defined in the following table (ignoring 64 bits!):<br>
<br>
/-------\<br>
Default   |16 | 32|<br>
+-------+<br>
Prefixed  |32 | 16|<br>
\-------/<br>
<br>
Now that you know how all prefixes effects, I will describe how prefixes affect string instructions, using examples:<br>
(Decoding mode is 16 bits)<br>
AD ~ LODSW<br>
66 AD ~ LODSD<br>
F3 AC ~ REP LODSB<br>
F3 66 AD ~ REP LODSD<br>
F3 3E AC ~ REP LODS BYTE DS:[SI]<br>
F3 67 AD ~ REP LODS WORD [ESI]<br>
<br>
Notice that if the instruction is not required to be in the long form, it has a suffix letter which represents the operation size.<br>
The long form of the string instructions are displayed when you change their address form or segment override them, which makes it explicit.<br>
<br>
/----------------\<br>
|Mandatory Prefix|<br>
\----------------/<br>
The mandatory prefixes are used as opcode bytes in special cases.<br>
Their values can be one of: 0x66, 0xf2 or 0xf3.<br>
The mandatory prefix byte must precede the first opcode byte, otherwise it is decoded just as a normal prefix.<br>
When a prefix is detected as a mandatory prefix, its behaviour isn't taken into account as a normal prefix.<br>
SSE instructions use the mandatory prefixes as part of the opcode itself,<br>
it makes life a bit harder when fetching an instruction in the fetching phase.<br>
This is covered thoroughly in the Decoding Phases!<br>
<br>
/--------------------\<br>
|REX Prefix - 64 Bits|<br>
\--------------------/<br>
REX stands for register extension.<br>
One of the most important changes in 64 bits is that it permits access to 16 registers.<br>
The REX prefix takes place <b>only<br>
<br>
Unknown end tag for </b><br>
<br>
 in 64 bits decoding mode.<br>
<br>
'till now all you had is 8 general purpose registers.<br>
Later on, I'm going to cover how the ModR/M is formatted and I will refer to the REX as well, so you see how it's related.<br>
<br>
Anyways, the REX prefix must precede the first byte of the opcode itself, otherwise it is ignored.<br>
I know I just wrote this same sentence about the mandatory prefix, but the REX prefix has a higher priority, calling it so.<br>
So if there is a REX prefix set and a mandatory prefix is set as well, they won't interfere with each other!<br>
It just comes out that the REX prefix has to be before the opcode itself, even if the mandatory prefix is set.<br>
And the mandatory prefix should be set before the REX prefix if it's set, and before these two all other prefixes can precede, no matter their order.<br>
<br>
The range of the REX prefix is 0x40 to 0x4f.<br>
It means that in 64 bits it overrides the instructions INC and DEC, but these instructions have an alternative opcodes, so no worry.<br>
<br>
So if we encounter a byte with the first (high) nibble with the value of 4, we know it's a REX prefix.<br>
The REX is formatted as follows:<br>
<br>
-7---4--3---2---1---0-- <-- Bits Index<br>
| REX | W | R | X | B | <-- Field Name<br>
\---------------------- <-- End Line Marker<br>
<br>
REX - 0x4, marks it is a REX prefix.<br>
<b>W<br>
<br>
Unknown end tag for </b><br>
<br>
idth - 0, default operand size. 1, 64 bits operand size.<br>
Here is how the REX.W flag affects the final operand size of the instruction:<br>
<br>
<br>
/-----------------------------------\<br>
|Default   |Default  |With   |With  |<br>
|Operating-|Operand- |0x66   |REX.W |<br>
|Mode      |Size     |Prefix |      |<br>
|----------+------------------------|<br>
|64 Bits   |  64     |IGNORED|  1   |<br>
|-----------------------------------|<br>
|64 Bits   |  32     |  16   |  0   |<br>
|-----------------------------------|<br>
|64 Bits   |  16     |  32   |  0   |<br>
\-----------------------------------/<br>
<br>
REX.W with a value of 0 causes no change to the operand size of the instruction.<br>
But a value of 1 causes the operand size to be 64 bits.<br>
Note that if a REX.W is 1 and an operand size prefix (0x66) is also set, then the 0x66 byte is fully ignored!<br>
However, if an operand size prefix is set and the REX.W is clear, that operand size will affect the instruction as well.<br>
REX.W won't affect byte operations as well as operand size prefix.<br>
<br>
So you see, when you disassemble instruction in 64 bits and a REX.W is set, the effective operand size becomes 64 bits.<br>
Now all instruction support 64 bits, that is their operands' types.<br>
On the contrast, there are some instructions that in 64 bits decoding mode their effective operand size becomes 64 bits by default,<br>
they are called promoted instructions. There is a limited list of promoted instructions,<br>
for example when you push a register in 64 bits you don't need the REX prefix to tell the processor it's a 64 bits register...<br>
<br>
<b>R<br>
<br>
Unknown end tag for </b><br>
<br>
egister field - 1 (high) bit extension of the ModR/M REG field.<br>
inde<b>X<br>
<br>
Unknown end tag for </b><br>
<br>
 field - 1 (high) bit extension of the SIB Index field.<br>
<b>B<br>
<br>
Unknown end tag for </b><br>
<br>
ase field - 1 (high) bit extension of the ModR/M or SIB Base field.<br>
<br>
Later on, I will explain precisely how these bits affect the decoding of registers.<br>
I just wanted to make sure you get familiar with them first.<br>
<br>
It is not true to assume that a REX prefix with a value of 0x40 doesn't have any implications on the instruction it precedes!<br>
<br>
/------\<br>
|Opcode|<br>
\------/<br>
Opcode is the static portion of the instruction which leads to (defines) the instruction itself.<br>
It is the bytes (and bits) you read from a stream in order to determine what instruction it is.<br>
The opcode size can vary from 1 bytes to 4 bytes. And it may also include 3 more bits from the REG field of the ModR/M byte.<br>
The instruction fetching mechanism in the disassembler is based on opcodes only<br>
(there could be tables which convert from ModR/M value to a string...).<br>
It is explained below how the fetch mechanism works with more info about the opcodes' varying sizes.<br>
Most of the instructions belong to two types: 8 bits instructions, and 16/32 bits instructions (could be prefixed...).<br>
The 16 or 32 bits operation size is set according to the decoding mode. I mentioned it earlier in the operand size prefix paragraph.<br>
Instructions which operate on 8 bits ignore operand size prefix.<br>
There are some instructions which are 5 bits long and the 3 other bits are used as the REG field,<br>
but treated as a whole byte instruction (for example: 40, 41 disassmbles to: inc ax; inc cx).<br>
<br>
The machine code of the opcodes is more complex than bytes granularity.<br>
I found it easier to treat opcodes as whole bytes and if required using the REG field as well.<br>
It simplifies stuff and makes the DB smaller, including its hierarchic structure (Trie data structure).<br>
<br>
/------\<br>
|ModR/M|<br>
\------/<br>
Some instructions require the ModR/M byte in order to specify the operands' forms.<br>
And some other instructions have the operands' types known in advance by their opcode only and don't need the ModR/M byte in order to specify them.<br>
The ModR/M byte is optional. The ModR/M could lead to a sequential SIB byte in 32 or 64 bits decoding modes.<br>
The opcode of the instruction itself has info about the operands' types, but these types, still could be<br>
extended in some ways, for instance, having an immediate number, or just a bit more complex effective-address.<br>
The role of the ModR/M is to define whether a SIB byte, an immediate or a displacement are required.<br>
And more than that, it defines the registers in use, according to the operands' types.<br>
The ModR/M is built from 3 fields:<br>
<br>
-7---6--543---210--<br>
| MOD | REG | R/M |<br>
\-----------------/<br>
<br>
The MOD field is the two most significant bits, it defines whether a displacement is used, and if so, its size.<br>
Well, and a few more things, keep on reading. Ah and MOD stands for Mode, how original.<br>
<br>
/----------------\<br>
|MOD       | Bin |<br>
|----------+-----|<br>
|No DISP   | 00  |<br>
|DISP8     | 01  |<br>
|DISP16/32 | 10  |<br>
|REG       | 11  |<br>
\----------------/<br>
<br>
MOD<br>
00 means no displacement is used.<br>
01 requires a displacement of 8 bits.<br>
10 requires a displacement of 16 or 32 bits, the size is set by the decoding mode, and could be altered by (operand size) prefix, of course.<br>
11 means that only general-purpose registers are in use.<br>
<br>
The famous REG field (3 bits).<br>
The REG field is used in order to specify the register of one of the operands, if used, of course.<br>
(The REG field defines the source or destination operand, it depends on the opcode itself).<br>
However, the special thing about it, is that it could be used just as a <i>part<br>
<br>
Unknown end tag for </i><br>
<br>
 of the opcode.<br>
This merely 3 bits are used many times in many instructions (0x80-0x83).<br>
Later on, it is explained how it becomes a part of the instructions DB.<br>
<br>
At last, but not least, the R/M field. The R/M field stands for Register or Memory.<br>
It has a different meaning, and its meaning is chosen according to the MOD field.<br>
It might be a general-purpose register when MOD is 11, or it might be a register for memory addressing when MOD is not 11.<br>
<br>
Notice that the operation size of the instruction wasn't mentioned yet,<br>
this is because for the ModR/M itself, the operation size isn't a matter.<br>
It becomes usable when you know the operands' types of the instructions,<br>
so with both parameters you will know what registers are used.<br>
<br>
The REG field or R/M field could be one of the following:<br>
<br>
-:Value to Register Table (32 bits):----<br>
|0   |1   |2   |3   |4   |5   |6   |7  |<br>
|EAX |ECX |EDX |EBX |ESP |EBP |ESI |EDI|<br>
|AX  |CX  |DX  |BX  |SP  |BP  |SI  |DI |<br>
|AL  |CL  |DL  |BL  |AH  |CH  |DH  |BH |<br>
|SS0 |SS1 |SS2 |SS3 |SS4 |SS5 |SS6 |SS7|<br>
|MM0 |MM1 |MM2 |MM3 |MM4 |MM5 |MM6 |MM7|<br>
\--------------------------------------/<br>
<br>
The only way to know which registers set you should use is by the operand type itself,<br>
and of course by the corresponding field's value.<br>
<br>
Let's decode some (in 32 bits) :)<br>
<br>
88 1B MOV [EBX], BL<br>
<br>
So 88 is a 8 bits operation size instruction.<br>
According to the specs 88 is defined as: MOV r/m8,r8<br>
<br>
In short, the first operand type: r/m means the operand could be a register or a memory addressing.<br>
The number following the r/m means the size of the instruction's operation.<br>
The other operand type, r8 or r32, means that the operand must be a register, its size is known too.<br>
<br>
Now that we know what's going on with these two operands and what to expect let's examine some bits:<br>
<br>
0x1B in binary is 00011011, making it ModR/M compatible: 00-011-011<br>
Knowing in advance the operands' types and the ModR/M, let's disassemble the instruction:<br>
88 is decoded as: MOV,<br>
The MOD is 00, means only a register for memory addressing is used.<br>
But how do we know which operand uses what field (REG or R/M), that's according to the operand type.<br>
So the R/M field used in this case as the Destination (=first) operand and has the value of 011, which is (3) EBX,<br>
and we know it's an R/M operand, thus it is a memory indirection form.<br>
We are left with the REG field, which in this case is also used, its value is 011 and decodes to (3) BL,<br>
it's BL and NOT EBX because the operand size is 8 bits, see that.<br>
<br>
Ok, another one:<br>
According to the specs:<br>
F6 /3 NEG r/m8<br>
<br>
Let's decode some more hex (in 32 bits) :<br>
F6 19<br>
<br>
Two things to note, the "/3" means it uses the REG field (as a part of the opcode!) with a value of 3 for indicating it's a NEG instruction.<br>
And the second thing, that it is a simple one-operand instruction.<br>
<br>
So encountering F6, we know it's a "NEG" instruction, alright.<br>
NO, that was not right! Encountering F6, we still don't know it's a NEG instruction, it could be something else,<br>
but we will know that we have to read the REG field in order to get the desired instruction, so after isolating the REG field,<br>
and testing it, we know it's the "NEG" instruction - now it's alright, for real.<br>
You see, reading F6 tells us that we have to read 3 more bits (REG),<br>
and only then we'll know the instruction, maybe if we read the REG we reach to another instruction,<br>
for example: F6 /6 is the DIV instruction.<br>
It's can't be that reading F6 tells us to read another whole byte for constructing the opcode, because then we would have collisions...<br>
Getting the instruction, we know its operands, in this case only one operand.<br>
By now you should know that type of operand.<br>
<br>
0x19 in binary ModR/M style is 00-011-001<br>
Notice that this time the REG field is indeed 3, which is the missing bits (1 byte, 0xf6 isn't enough to determine the instruction),<br>
which completes the opcode fetching.<br>
So the REG field was already used and is ignored for operand decoding.<br>
We know MOD of 00, so we look up the table and get [ECX] (because R/M=1).<br>
Eventually the instruction is decoded as: NEG BYTE [ECX]<br>
The "BYTE" is an addition to show the operation size explicitly,<br>
otherwise you could keep on guessing the operation size of this instruction, without having any clue.<br>
<br>
As you can see,<br>
there are 3 ingredients to a good instruction :)<br>
An opcode (which is a must, of course)<br>
and is bundled with the operands' types (in fact, this is 2 in 1 :).<br>
And ModR/M which is optional, but necessary most of the times.<br>
<br>
There are a few quirks to the ModR/M decoding,<br>
how to get from a ModR/M to SIB wasn't explained yet.<br>
It varies from 16 to 32 bits, which have different tables for decoding the ModR/M,<br>
but I will stick to the 32 bits version, as I have already done.<br>
Note that 16 bits don't have a SIB byte, thus there are no complex memory addressings in 16 bits.<br>
<br>
The ModR/M byte when decoded to specify the ESP as a memory addressing register, actually tells the processor to read the SIB byte!<br>
This is because when the R/M field's value is 4 (ESP register) it means the instruction includes the SIB byte,<br>
so in order to really specify an operand as ESP, we will have to use a SIB byte for that.<br>
<br>
And there is another special case when MOD is 00 and R/M is 5 (EBP register) it means the EBP is NOT used at all,<br>
and that a Displacement of 32 bits follows the ModR/M byte.<br>
That's why using the EBP register as memory addressing register takes one more byte (using MOD=01, Disp8=0), making it [EBP+00].<br>
I guess Intel chose the EBP register instead of the others, because EBP is intended as a stack frame pointer, and will have a disp8 offset.<br>
So it's not big deal to pay one more byte for the instruction when we usually use that byte anyways...<br>
The special R/M=5 case, allows the instructions to use an absolute memory address, for example:<br>
MOV [0x1234567], EBX<br>
Otherwise it wasn't possible using only ModR/M.<br>
<br>
-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-64 bits decoding mode + ModR/M-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~<br>
<br>
If that was the same case in 64 bits decoding mode, when the R/M is 5 then the result was:<br>
MOV [RIP+0x1234567], EBX<br>
So when R/M is 5, the RIP or Register-IP becomes the base register.<br>
And if you still want an absolute addressing in 64 bits mode, you will have to use the SIB byte with a couple of tricks.<br>
Yes, you actually can get the position of the currently being executed code with LEA RAX, [RIP+0] Genius!<br>
<br>
Back to REX prefix now. This is the most hard part in 64 bits decoding, so pay extra attention:<br>
so if the REX.R is set, the REG field of the ModR/M becomes a 4 bits variable which indicates a register index.<br>
And if the REX.B is set, the R/M field of the ModR/M becomes a 4 bits variable...ditto.<br>
<br>
All the above extreme cases of the EBP/ESP reigsters don't apply to this new variable,<br>
it means that even if the REX.R is set, a RIP will be used, or a SIB will be read if the REX.R is set and REG is 4...<br>
Sometimes the REX bits are ignored and the other times they are took into account, it depends what action is being done,<br>
it is all covered in the AMD64 documentation really well, in the bottom line,<br>
the REX is ignored when the fields tell the processor to read the SIB byte or in the extreme cases explained earlier.<br>
<br>
A fourth bit in the REG or R/M field permits access to 16 registers.<br>
There are new sets of registers for 64 bits.<br>
<br>
These are the 64 bits registers:<br>
/-----------------------------------------------------------------------------\<br>
|RAX |RCX |RDX |RBX |RSP |RBP |RSI |RDI |R8 |R9 |R10 |R11 |R12 |R13 |R14 |R15 |<br>
\-----------------------------------------------------------------------------/<br>
<br>
Even 32 bits registers can be extended!<br>
/-------------------------------------------------------------------------------------\<br>
|EAX |ECX |EDX |EBX |ESP |EBP |ESI |EDI |R8D |R9D |R10D |R11D |R12D |R13D |R14D |R15D |<br>
\-------------------------------------------------------------------------------------/<br>
<br>
Further 16 bits registers can be extended using the suffix letter 'W' instead.<br>
<br>
In 64 bits decoding mode, there is a new set of registers accessible, the low bytes of SI, DI, BP and SP!<br>
I wonder how compilers will use these bytes in the future...<br>
Anyways, there are two tables now:<br>
<br>
8 bits registers <b>without<br>
<br>
Unknown end tag for </b><br>
<br>
 REX prefix (nothing special yet):<br>
/-----------------------------------------------------------------------------\<br>
|AL |CL |DL |BL |AH |CH |DH |BH |R8B |R9B |R10B |R11B |R12B |R13B |R14B |R15B |<br>
\-----------------------------------------------------------------------------/<br>
<br>
8 bits registers <b>with<br>
<br>
Unknown end tag for </b><br>
<br>
 REX prefix set (no matter its flags!):<br>
/---------------------------------------------------------------------------------\<br>
|AL |CL |DL |BL |SPL |BPL |SIL |DIL |R8B |R9B |R10B |R11B |R12B |R13B |R14B |R15B |<br>
\---------------------------------------------------------------------------------/<br>
This explains why a REX prefix with a value of 0x40 might affect the instruction, even with all bits cleared!<br>
<br>
Note that the extended 32 bits registers could be used in memory addressing forms!<br>
For example: INC DWORD [R8D + R15D * 8 + 0x1234].<br>
<br>
One more comment about 64 bits -<br>
the default addressing size is 64 bits, wheareas the default operand size is 32!<br>
/--------------------------------------\<br>
|Default   |Default  |With   |Effective|<br>
|Operating-|Address- |0x67   |Address- |<br>
|Mode      |Size     |Prefix |Size     |<br>
|----------+---------------------------|<br>
|64 Bits   |   64    |  No   |   64    |<br>
|--------------------------------------|<br>
|64 Bits   |   64    |  Yes  |   32    |<br>
\--------------------------------------/<br>
<br>
BTW - there are 16 XMM registers (SSE) as well in 64 bits.<br>
<br>
/---\<br>
|SIB|<br>
\---/<br>
SIB stands for Scale-Index-Base, it is a one byte which embodies these fields.<br>
It is an optional byte and if used, it must be sequential to the ModR/M byte.<br>
The SIB might be a part of the instruction only when the operand is in the addressing mode (MOD!=11).<br>
The SIB makes the effective address more powerful, thus using less instructions in order to calculate complex addresses.<br>
<br>
It formats as:<br>
<br>
-7-----6-5-----3-2----0-<br>
| SCALE | INDEX | BASE |<br>
\----------------------/<br>
<br>
And results in [INDEX * 2**SCALE + BASE].<br>
<br>
The most significant two bits represent the SCALE field.<br>
The scale field is used as a multiplication variant for the Index register.<br>
The Index is multiplied by 2**Scale (powered), the Index register (3 bits long) could be any general-purpose register,<br>
except the ESP register, makes sense, doesn't it?<br>
<br>
The Base register is 3 bits long (less significant) and is used as a base address.<br>
There is a special condition to this register, the base is ignored when it's the EBP register and MOD==00, recall it means<br>
using a displacement of 32 bits.<br>
<br>
In the bottom line, the special case comes to our call in 64 bits,<br>
when we can't use an absolute memory address only (because then RIP is the base register automatically),<br>
we are left with a special case:<br>
If the MOD=00 and Base=EBP and Index=ESP, we end up with disp32 only.<br>
Therefore even in 64 bits you can use absolute addresses!<br>
<br>
So before we know which registers we are going to use,<br>
we still have to decode the REX prefix, that is in 64 bits mode, and see how its flags affect the SIB.<br>
REX.R is ignored when decoding SIB, because in order to read a SIB byte the REG field had to be 4.<br>
<br>
So we are left with two more flags:<br>
The REX.X flag is quiet easy to understand, it is only used as the high fourth bit of the Index field.<br>
And the REX.B flag, which becomes the high fourth bit of the Base field.<br>
<br>
If you are still confused, you should take a look at the AMD64 data sheets,<br>
they have nice graphs describing these REX bits things...<br>
<br>
<br>
/------------\<br>
|Displacement|<br>
\------------/<br>
The displacement is optional, it might be used only if the R/M field defines so (recall the R/M table above).<br>
The size of the displacement could vary from 1 byte, 2 bytes or 4 bytes, the MOD and R/M field define it too.<br>
This field must follow the ModR/M byte or SIB byte if exists.<br>
If this field is used, it will be used as part of the address.<br>
The address size prefix affects the size of the displacement<br>
(this is because it tells us to use the non-default addressing table, which has different definitions for the displacement).<br>
In memory the displacement is stored in Little Endian.<br>
<br>
/---------\<br>
|Immediate|<br>
\---------/<br>
Instructions could load values into registers or use plain number in order to do other operations.<br>
Instead of loading those values off the memory, they could be part of the instruction itself, hence their name.<br>
The immediate could be treated as a signed number, and its size varies from 1 byte, 2 bytes or 4 bytes,<br>
its size is dependant on the decoding mode and the (possibly set) prefixes.<br>
The immediate is the last element in the instruction, and is stored in Little Endian.<br>
</pre>