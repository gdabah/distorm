This is your number 1 documentation if you wish to tinker with diStorm on your own, it was written for diStorm64, and it is not up to date, but should be good enough to understand how diStorm works.

<pre>
/-------------------\<br>
|Trie Data Structure|<br>
\-------------------/<br>
A decent technical explanation could be found at http://en.wikipedia.org/wiki/Trie .<br>
I decided to use the Trie data structure in order to find an instruction at O(1) instead of searching<br>
it using a mask at O(n) where n is number of instructions in the data base.<br>
<br>
The way it works is quiet easy to follow, there's the root instructions table, consists of 256 entries,<br>
each entry holds a structure which tells you if you got the instruction or if you should keep on reading<br>
more bytes or bits (in the 80x86 case).<br>
The structure which defines a node (entry) in the table has to describe whether you got all bytes read<br>
and thus, you got to the instruction itself, or whether you have to read some more bytes, using a type value<br>
which indicates one of the two options. Or the third option, which says there is no instruction at this entry.<br>
80x86 instructions have a varying length, that's why a Trie data structure fits in comfortably. Not mentioning,<br>
the minimal fetching timing.<br>
<br>
typedef struct InstNode {<br>
unsigned char type;<br>
union {<br>
InstInfo* ii;<br>
struct InstNode* list;<br>
};<br>
} InstNode;<br>
<br>
Reading a byte from a stream, you access to the root table with that byte as an index. You will end up reading an InstNode,<br>
then examining the type, you know whether you found the instruction, or maybe you should read some more.<br>
If you should read some more, then you read the next byte in the stream and then advance to the next table in the<br>
Trie data structure, using the InstInfo pointer, which leads to another table. Reading the next byte as an index within<br>
this table, results in another read of InstNode structure, then you examine the type 'till you get an instruction<br>
information structure. Or maybe the type says you got to the end of the road, so no instruction exists using the bytes<br>
you read from the stream. In 3 hops at most you are supposed to find the instruction, if exists. Thus no loops are needed,<br>
and the fetch timing is at O(1), which is huge advantage over other disassemblers. 3 hops is the maximum depth because 80x86<br>
compatible instructions (to be accurate - opcodes that is) are 3 bytes long at most.<br>
<br>
The 80x86 has a complex instruction sets, therefore reading a whole byte at a time isn't enough. Sometimes,<br>
you have to read a whole byte and 3 more bits in order to get to the desired instruction. In the references it's called<br>
Groups. The most familiar groups are 0x80-0x83. This makes the fetching code a bit more complicated. And some other instructions<br>
have an opcode of a minimal 5 bits length, but because we seek the table with bytes granularity, we will have to treat these instructions<br>
specially. FPU instructions are divided into two types, depending on their second opcode byte's value. This split is required in order to<br>
distinguish between these types, one type is used for constant 2 bytes FPU instructions and the other for using the second FPU opcode byte<br>
as a ModR/M byte. The type is determined according to the second byte's range. This gets more complicated when decoding some SSE instructions.<br>
<br>
There are 6 types of InstNode:<br>
typedef enum {<br>
INTNOTEXISTS = -1,<br>
INTNONE,<br>
INTINFO,<br>
INTLISTGROUP,<br>
INTLISTFULL,<br>
INTLISTDIVIDED<br>
} InstNodeType;<br>
<br>
INTNOTEXISTS - no instruction information is found, this means we should drop the bytes we read.<br>
INTNONE - list or ii aren't set.<br>
INTINFO - an instruction was found, ii describes the instruction information for decoding.<br>
INTLISTGROUP - list points to a group table (3 bits, REG field in the ModR/M),<br>
so when you read the next byte, use only 3 bits as an index.<br>
INTLISTFULL - list points to a full table (256 entries), so read another whole byte.<br>
INTLISTDIVIDED - list points to a special table (72 entries), used for FPU instructions' complexity and some other sets.<br>
<br>
The Trie data structure as used in this project is pre-built, statically initialized in the data segment.<br>
The main advantages for this behaviour is that initalization time is spared and no memory should be consumed in run time.<br>
The way instructions (as in the trie data structure described above) are formated in memory is for fetching speed's sake.<br>
It appears to be a bit wasteful, although it could be more optimized in the memory form, making it slightly slower.<br>
I'm going to cover the way it is used currently in this project, and the better memory way, in case anyone wishes to optimize it.<br>
Well, to be honest I didn't manage to come up with anything better and I think the current mechanism is quiet alright.<br>
<br>
Eventually, we have three types of tables: 256, 72 entries and 8 entries. Reading a whole byte or reading 3 bits (REG field)<br>
from the next byte, respectively. It might be that some tables will be mostly empty, because not many instructions are<br>
defined using these bytes. Thus, we end up having gaps in our tables, because not all entries are set to INTINFO in the last table.<br>
Let's say we have the root table, called Instructions, its size is 256, of course, because all 80x86 instructions are at least 1 byte long.<br>
People might claim that I am not accurate, because for instance, push instruction is five bits long and the other 3 bits specify the register,<br>
but it all depends how you represent and use your data, later on I will shed some light about those special cases.<br>
All the entries in the root table are taken, except prefixes' values, which could lead nowhere. So the root table is quiet well used,<br>
now if there are two bytes long instructions, we have to allocate another table. Say the instructions which start with 0x0F.<br>
Getting Instructions at index 0x0F'th leads you to another table with 256 entries, because there are instructions of 2 bytes<br>
and more using the first opcode byte as 0x0F. This 0x0F's table will be partly used, because the instructions defined for 0x0F don't use all entries.<br>
And some of the instructions even require 3 more bits from the third byte in the stream, leading to another table of 8 entries.<br>
Again, not all entries in that 8 entries' table are in use.<br>
There are many entries which are not in use, but it saves us another byte fetch at the cost of O(1) in the fetching code of an instruction.<br>
That's because we simply read the table at index X, where X is the byte (or 3 bits) read from the stream, this way avoiding bounds overflow.<br>
The 72 entries table will be explained later, it's quiet confusing, so let's continue with the basics first.<br>
<br>
An example of a Trie DB:<br>
Where FULL = 4 entries and GROUP = 2, for the sake of example.<br>
ROOT:<br>
0 - INTINFO<br>
1 - INTGROUP<br>
2 - INTINFO<br>
3 - INTNOTEXISTS<br>
<br>
Group table for ROOT[1]:<br>
1, 1 - INTINFO<br>
1, 2 - INTNOTEXISTS<br>
<br>
Reading one byte (in the range of 0-3...), you can retrieve the correct entry directly for that index.<br>
Let's parse this stream according to the ROOT in the example:<br>
0, 0, 1, 0, 1, 1<br>
<br>
Offset 0: ROOT[0] results in INTINFO, an instruction was found. So decode it and get to the next byte, restarting the whole process.<br>
Offset 1: ROOT[0] ditto.<br>
Offset 2: ROOT[1] results in INTGROUP, thus in this table we know we have to read only 2 bits from the second byte of the instruction.<br>
Offset 2,3: ROOT[1, 0] results in INTINFO. Start all over.<br>
Offset 4: ROOT[1] results in INTGROUP. Get second byte...<br>
Offset 4,5: ROOT[1,1] results in INTNOTEXISTS, ah uh, no instruction defined.<br>
<br>
As you can see there are two undefined instructions. In this table it's nothing special,<br>
but when you have 80x86 tables, you will have many undefined instructions, thus wasting space.<br>
In this project, I prefered to ignore the undefined instructions, which don't cost much space in memory and spares<br>
some time in fetching instructions. If you really want to omit undefined instructions from your tables, I can only<br>
suggest one technique. Every table will have an array of its size, using the above example, 4 cells in the ROOT table<br>
and 2 cells in the GROUP table. Every cell in the node will be an index into the InstNode in that table, thus undefined<br>
instructions take only 1 byte instead of a few for an empty InstNode.<br>
<br>
So using this technique the new Trie DB appears like this:<br>
ROOT:<br>
[0,1,2,-1]<br>
0 - INTINFO<br>
1 - INTGROUP<br>
2 - INTINFO<br>
<br>
Group table for ROOT[1]:<br>
[0,-1]<br>
1, 1 - INTINFO<br>
<br>
This way we eliminate INTNOTEXISTS InstNodes using the -1 marker for "undefined".<br>
You should say by now that -1 is a bit problematic. If you have 256 instructions and the index consists from 1 byte,<br>
then it will simply direct you to the last entry, and you won't be able to tell the difference from Undefined to an index to the last entry.<br>
So there are many ways to solve this problem, using a base and limit offsets for the indexing array, making it even smaller.<br>
Or defining the indexing array as shorts, but then maybe you should make it DWORDs, because it will be read faster in Pentiums.<br>
It's an endless story, the best way to know which technique and data type fit, is to test it all. I find the current algorithm good enough.<br>
<br>
It might be that this technique, even saving memory space, but in the price of one more fetching (for the indexing-array) is still faster<br>
than the current implemented mechanism, because of its small size it can be cached more easily. Though, I haven't tested it yet.<br>
There are many ways to implement Trie data structure as you can see. I didn't put too much efforts on the Trie DB, my goal<br>
was to find an instruction in 3 byte fetchings (at most) at O(1). The techniques in this documentation could be developed to more<br>
optimized forms, if it's a memory space or a fetching time tradeoff.<br>
<br>
2 bullets I think you should know:<br>
1.The first version of diStorm used a dynamic allocated instruction tables.<br>
Which I started to dislike with time. The true reason is that I hated calling the initialization and destruction routines<br>
of the dynamic tables everytime I wanted to use the disassembler. Knowing that the dynamic tables are found in the resource<br>
segment anyways, I found it easier and more comfortable to keep them static tables that way.<br>
Which means you can just start using the ROOT of the Trie DB, without fretting for anything.<br>
<br>
2.Another decision I had to make is to support all 80x86 instructions in my DB, with the exceptional of 3DNow!<br>
and the WAIT instruction. In 'support' I mean that the code that fetches an instruction won't have to contain if statements<br>
for searching/looking for a specific instructions or groups. Most of the disassemblers out there mix instruction tables<br>
with code. I wanted that piece of code, which locates an instruction, to find that instruction according to the Trie DB only.<br>
And yes, it makes matters a bit more complicated (divided instructions...), and I am not sure whether I gain timing here,<br>
but I find it more reasonable and organized this way. The DB defines all instructions; and instructions shouldn't be<br>
defined in the code itself.<br>
<br>
/-----------------------\<br>
|Instruction Information|<br>
\-----------------------/<br>
The instruction information has a major role in the disassembler.<br>
We need the instruction information structure for two important reasons:<br>
first of all, we know whether we reached an instruction in the Trie DB (from the given stream)<br>
and we have to get the information about the instruction itself.<br>
<br>
Information such as:<br>
typedef struct PACKED {<br>
unsigned char s, d;<br>
char* mnemonic;<br>
iflags flags;<br>
} InstInfo;<br>
<br>
This is the base structure, as you can see it defines a few things about an instruction,<br>
its source and destination operand types, its mnemonic and flags describing the behaviour of the instruction.<br>
<br>
There are more types of InstInfo structure, they are 'deriving' from the base InstInfo above.<br>
I needed more types in order to define some more attributes to instructions that require so,<br>
because most of the instructions adequate with the InstInfo, I decided to spare some space (not defining more variables).<br>
This is the only place where I think C++ could be great in diStorm, but with a simple 'casting', it wasn't really necessary.<br>
<br>
Some instructions require 3 operands defined, for example, the IMUL and other SSE instructions.<br>
And there are other instructions which require 3 mnemonics (CWD, CBW, and JrCXZ).<br>
There are special cases where the second and third mnemonics are used as the suffix letters for the mnemonic,<br>
for example, the SSE pseudo compare instructions...blah<br>
<br>
So how do you know which type of structure you hold after fetching that opcode?<br>
In one word, flags.<br>
They tell you essential info about the opcode and the operands.<br>
<br>
There are many flags out there... I will name a few:<br>
(Take a look at instructions.h for the full list.)<br>
INSTINCLUDEMODRM - A ModR/M byte follows the opcode byte, so read it and decode it as well.<br>
INST32BITS - The instruction can't be disassembled in 16 bits!<br>
INSTPRELOCK - The instruction is lockable (means the lock prefix can precede it).<br>
INSTPREREP - The (I/O) instruction is repeatable (means the rep prefix can precede it).<br>
INST3DNOWFETCH - A 3DNow! instruction tells the disassembler to read one more byte to get its mnemonic...<br>
<br>
Some of the instruction's flags are treated distinctively when different operand types are decoded,<br>
you must make sure how that operand type acts upon that specific flag before you just clear it or set it.<br>
This applies also to the extra mnemonics that a several instructions have.<br>
<br>
/-----------------\<br>
|Opcodes In The DB|<br>
\-----------------/<br>
Now that you know how the Trie DB is built, I am going to cover how the fetch of instructions is being done.<br>
Starting with simplified instructions, then complex (FPU) instructions and at last, mandatory prefixes' mess.<br>
In the 80x86 the length of instructions vary. As it all began as CISC processors, we have to suffer for back compability.<br>
The Trie DB supports the following type of instructions:<br>
typedef enum {<br>
OCST1BYTE = 0<br>
OCST13BYTES,<br>
OCST1dBYTES,<br>
OCST2BYTES,<br>
OCST23BYTES,<br>
OCST2dBYTES,<br>
OCST3BYTES,<br>
OCST33BYTES,<br>
OCST4BYTES<br>
} OpcodeSize;<br>
<br>
For every opcode size I will show a real instruction example, hope it will make it easier to follow.<br>
The notation I use for instructions' sizes are:<br>
1/2/3 byte(s) long instruction (kinda straight forward).<br>
1.3 - A whole byte + 3 bits from the next byte, which represent the REG field from the ModR/M byte.<br>
2.3 - Two whole bytes + 3 bits from the next byte...<br>
3.3 - Three whole bytes + 3 bits from the next byte...You actually read it as "One Point Three bytes long instruction" and so on.<br>
The ".3" means you read another byte, but uses only the REG field from the ModR/M according to the specs,<br>
which means you read a whole byte in a 256 entries table and then you use 3 bits in a 8 entries table.<br>
And last but not least, 4 bytes instruction, this is new for the SSSE3 instructions set.<br>
<br>
1d, 2d - divided (range) instructions.<br>
To be honest, it's a misleading name.<br>
It's not the instructions theirselves that are divided, but the range of the second or third byte, respectively,<br>
that defines which instruction it is.<br>
Divided instructions are used for FPU instructions and are covered thoroughly below.<br>
<br>
Fixed length instructions:<br>
OCST1BYTE - 0x9c: PUSHF<br>
OCST2BYTES - 0x0f, 0x06: CLTS<br>
OCST3BYTES - 0x9b, 0xdb, 0xe3: FINIT<br>
OCST4BYTES - 0x66, 0x0f, 0x3a, 0x0f;0xc0 (MODRM) 0x55 (IMM8) PALIGNR XMM0, XMM0, 0x55<br>
<br>
The REG field from ModR/M byte comes into play:<br>
OCST13BYTES - 0xf6, (REG field)4: MUL<br>
OCST23BYTES - 0x0f, 0x00, (REG field)4: VERR<br>
OCST33BYTES - 0x66, 0x0f, 0x73, (REG field)7: PSLLDQ<br>
<br>
Divided (range) instructions, according to ModR/M byte value:<br>
OCST1dBYTES - 0xd8, 0xd9: FCOMP<br>
OCST1dBYTES - 0xd9, (REG)0: FLD<br>
OCST2dBYTES - 0x0f, 0xae, (REG)1: FXRSTOR<br>
OCST2dBYTES - 0x0f, 0xae, 0xe8: LFENCE<br>
<br>
As you can see, reading a byte and using it as an index in the ROOT table, then testing the type,<br>
lets you know whether you are required to read another byte, or another byte for its 3 bits AKA the REG field.<br>
In 80x86 the FPU instructions have are split to two ranges, from 0x0 to 0xbf and from 0xc0 to 0xff.<br>
If the second or third byte (depends on the instruction's opcode) of the instruction lies within the first range,<br>
then this instruction uses the second byte as a ModR/M byte, thus you will know what instruction it is,<br>
using the REG field in the ModR/M as an index into a group table. If the second or third byte (depends<br>
on the instruction's opcode) of the instruction lies within the second (high) range, then this instruction uses the<br>
second byte as a whole, so it becomes a normal two bytes long instruction.<br>
<br>
The reason the ranges are split on 0xc0 is because in ModR/M value the two upper bits (most significant) represent the MOD.<br>
If the MOD is 11b, according to the specs, it means the operation of the instruction is being done on registers and not memory.<br>
In the FPU instructions set it's not possible for an instruction to use a general-purpose register (that's why MOD=11 is not useful).<br>
So MOD!=11 uses memory indirection and this range (0x0-0xbf) of the ModR/M is enough to define an instruction with its operands in this case.<br>
This leaves the upper range (0xc0-0xff) for static instructions, makes them 2 bytes long instructions.<br>
<br>
In practice, the way a divided table is stored goes like this, this is the 72 entries table story:<br>
From the preceding paragraph we learnt that these divided instructions actually require Group table and a Full table.<br>
But in practice, we know that we don't really need a full table, this is because the upper range only uses that full table,<br>
and the upper range itself is from 0xc0 to 0xff. So we can merge both table and save some space. 72 is the sum of 8 entries for Group table<br>
and 64 entries for the upper range. A table of 72 entries is allocated then, if the instruction is two bytes long and static (upper range), then<br>
we use the entry which is read using the index of the second byte's value subtracted by 0xb8 (skipping the first 8 entries, but it's 0xc0 based).<br>
So far so good, if it's the lower range, (remember that we know we are expecting a divided instruction) we isolate the 3 bits of the REG field,<br>
shift them to the right (making them zero-based) and accessing that entry in the table, this way we get to the low range instructions.<br>
<br>
* Note that in diStorm, unlike Intel's specifications, the nubmer of bytes (in OCS types) COUNTS the mandatory byte!<br>
<br>
/-------------------\<br>
|3DNow! Instructions|<br>
\-------------------/<br>
The 3DNow! instruction set is kinda tricky, when I saw them for the first time, I said "What the heck?!", that was after I calmed down...<br>
The format of a 3DNow! instruction doesn't follow the normal 80x86 architecture, so they have to be treated specially.<br>
Luckily, it's not magic after all, it goes like:<br>
<br>
/-------------------------------------------------------------\<br>
| 0x0F | 0x0F | ModR/M | *SIB | *DISPLACEMENT | 3DNow! Opcode |<br>
\-------------------------------------------------------------/<br>
* means the element is optional.<br>
<br>
The first thing you should be asking yourself is "How the heck will I decode the operands if I don't know their types?".<br>
Well, no worry, it was truely impossible if that was the problem. The matter is that they are fixed types.<br>
The first operand type is: MMREG,<br>
and the second operand type is: MMREG/MEM64.<br>
As you may know, the 3DNow! instructions set operates on MMX registers (MM0-MM7).<br>
<br>
The second operand says it could be defined to use another MMX register (recall MOD=11),<br>
or it could be a memory indirection addressing (MOD!=11), loading a 64 bits value off memory as an MMX value.<br>
<br>
After encountering two bytes in a row of 0x0F, you know you hit a 3DNow! instruction.<br>
The next thing you do is telling the decoder you know the operands' types already and feed them in brutally.<br>
Then when you are done messing with the ModR/M and the other optional elements you get the instruction's name<br>
(its mnemonic) by the last byte in the instruction.<br>
This happens using another function which will begin seeking the instruction from ROOT[0x0F][0x0F]->[3dNow Opcode Index].<br>
<br>
The extended 3DNow! instruction set works (formatted) the same way, so it only has to be inserted into the DB.<br>
<br>
/-------------\<br>
|Operand Types|<br>
\-------------/<br>
Reading the opcode of an instruction gives us its operands' types, without them we couldn't disassemble the instruction further.<br>
The following finite set is taken from the source code, it includes all possible types of the 80x86 instructions.<br>
<br>
The legend goes like this:<br>
OT< type>< size> = Operand Type, its real type by the specs and the size of the type.<br>
It's kinda self explanatory.<br>
One more thing, that 'FULL' suffix is a special size case, it means that the size of the type is either 16 or 32 bits (or 64...).<br>
The default size of 'FULL' depends solely on the decoding mode (that is passed in the API), and prefixes such as Operand Size,<br>
which switch the size to the non-default. It is all explained already in the Operand Size section, but this is how it's practically done.<br>
Let's have a simple example:<br>
PKUDA < OTREGFULL><br>
So if we disassemble that instruction (which is named PKUDA) in 16 bits (or prefixed with operand size in 32 bits),<br>
we can only use the general purpose registers such as: AX, CX, DX, BX, SP, etc...<br>
But if we disassemble that instruction in 32 bits, or prefix it with operand size in 16 bits,<br>
the general purpose registers become: EAX, ECX, EDX, EBX, ESP, etc...<br>
<br>
So 'FULL' tells the operand type decoder function to examine for set prefixes and the decoding mode itself, and decide its size on the fly.<br>
The rationale for naming it 'FULL' isn't so clever, I will just leave it this way.<br>
<br>
typedef enum OpType{<br>
<br>
For the complete updated list take a look at http://code.google.com/p/distorm/source/browse/trunk/src/instructions.h<br>
<br>
} OpType;<br>
<br>
The suffix 'RM' means that instead of decoding the register field from the REG bits, it will read it from the R/M bits of the ModR/M byte.<br>
This is crucial when the REG bits are already used as a part of the opcode itself.<br>
Except OTREG types, all types which are suffixed by a size means that they are part of a ModR/M byte.<br>
For example:<br>
OTXMM64, means that XMM register is used as a real register, or that it is stored/loaded to/fro memory.<br>
ADDPD OTXMM, OTXMM128 - ADDPD XMM0, [EBX]<br>
The memory pointed by EBX is used as an XMM variable with the instruction ADDPD.<br>
<br>
The Forced REG/RM types mean that the operand size is set according to the decoding mode and nothing else.<br>
Even in 64bits the instruction doesn't care about REX prefix and it will be promoted to 64 bits nevertheless.<br>
Let's see a practical example, same stream in both modes.<br>
32 bits: 0x0f, 0x78, 0xc1 VMREAD ECX, EAX<br>
64 bits: 0x0f, 0x79, 0xc1 VMWRITE RAX, RCX<br>
<br>
On the contrary, there are few instructions which needs the REX prefix in order to be promoted to 64bits.<br>
A good example might be the MOV REG, IMM32 which becomes MOV REG64, IMM64 ONLY when prefixed with a REX.W.<br>
<br>
It's time to cover the special 5 bits instructions (OTIBxxx).<br>
I decided to call them Instruction-Block because the REG field is extracted from the other 3 (LS) bits, but in the Trie DB they look as follow:<br>
0x40-0x47: INC < OTREGFULL><br>
0x48-0x4f: DEC < OTREGFULL><br>
0x50-0x57: PUSH < OTREGFULL><br>
And so on...<br>
Because the Trie DB works in a byte granularity, the trick I used was to define one instruction per a block which its operand size is OTIBxxx,<br>
where xxx is the operand's size. So when we encounter a byte in the range of 0x40-0x47 for instance, we read from the corresponding instruction's<br>
information structure an operand type of OTIBRFULL, which is interpreted in the operand type decoder function as "read the REG field from<br>
the lower 3 bits", and of course, because in this case the size is FULL, it means the decoding mode and the prefixes affect the actual register size.<br>
<br>
<br>
/---------------\<br>
|Decoding Phases|<br>
\---------------/<br>
There are a few basic steps that a disassembler have to do,<br>
they definitely depend on the way an 80x86 instruction is formatted.<br>
<br>
1) [Prefixes]<br>
So the first thing the disassembler does when it gets a binary stream (a pointer and a length) is looking for prefixes.<br>
You read the prefixes as long as there are bytes in the stream to read and basically, untill you hit another byte which isn't a prefix.<br>
There is one extra condition, 80x86 instructions can't be longer than 15 bytes, this rule includes prefixes as well.<br>
After reading the prefixes, we make sure that we didn't reach the end of the stream,<br>
if this is the case, we will simply drop all prefixes and exit the main loop.<br>
Extra prefixes will be dropped after examining the prefixes when they are being scanned.<br>
<br>
2) [Fetch Opcode]<br>
This is a quiet tricky routine, because if we read a mandatory prefix, we still don't know it is a mandatory prefix.<br>
So we have to look for an instruction that begins with that prefix and only if an instruction was found we know that that prefix was a mandatory one,<br>
and not a normal prefix.<br>
To get matters clear, here's an example:<br>
0x66, 0x0f, 0xc1 (this will get to the opcode XADD with the prefix(0x66) treated really as operand size).<br>
So how do we know whether 0x66 should be treated as a normal operand size prefix or as a mandatory prefix?<br>
This is done only by trying to fetch the instruction beginning with 0x66 in the Instructions (ROOT) table.<br>
If we don't end up with an existing instruction-information structure, we know that the 0x66 prefix should be treated as a normal operand size prefix.<br>
And the catch here, is to start fetching the instruction from the real non-prefix byte (in the example it's the byte 0x0f).<br>
<br>
0x66, 0x0f, 0x58 will get to the ADDPD opcode (SS2E).<br>
But you might ask, what about the stream 0x0f, 0x58, where this lead to?<br>
Well, you can reach an opcode from this stream, ADDPS (SSE).<br>
Here's how ADDPS is defined by the specs:<br>
ADDPD OTXMM, OTXMM128<br>
So you see, there is no need for an operand size prefix no matter what, it won't affect the instruction.<br>
This means that even if you encounter a mandatory prefix you can be sure it's there for a reason and a collision can't really happen.<br>
<br>
Eventually, the fethcing routine will return an instruction-information structure, which can be also NULL (means no instruction was found).<br>
<br>
3) [Filter Opcode]<br>
There are a few conditions we would like to make sure an opcode, we just got, meet.<br>
If the decoding mode is 16 bits and the opcode we got is only 32 bits, then it means we read an invalid opcode (we should drop it).<br>
Or maybe we read an opcode which is invalid in 64 bits decoding mode (there are a lot of invalid opcode in 64 bits).<br>
We also make sure there is a ModR/M byte read or maybe we have to read it now,<br>
this is because, as you know, the second byte of the FPU opcode is the ModR/M byte (yes - only if it's in the low range), so it means<br>
we already read the ModR/M byte and don't have to read it.<br>
But other opcodes don't contain the ModR/M byte as a part of the opcode itself, so in this step we will read it.<br>
Another type of opcodes is the xxx.3 bytes long instructions (the ones which require the REG field...), therefore we ought to read already<br>
ModR/M byte already, in order to locate that instruction using the extra 3 bits into a Group table.<br>
For 3DNow! instructions, we have to see whether we read 0x0f, 0x0f (3DNow! opcode base) and change the pointer we got from the second step<br>
to point into a special instruction information structure which describes the operands' types of a 3DNow! instruction<br>
(remember we can't find the instruction because its reversed format?).<br>
<br>
4) [Extract Operand(s)]<br>
This is an important step,<br>
we will call a function which will textually format the operand according to the bytes in the stream.<br>
This function will use the ModR/M we read earlier in order to determine some vuage information about the operands.<br>
It will then read a SIB byte if required and decode it also.<br>
<br>
For each operand in the opcode we read, we will extract its operand.<br>
Just to remind you that an 80x86 instruction could have up to 3 operands.<br>
<br>
The extraction routines are the core of the disassembler, they will analysis the operands types<br>
and act upon them. If required an immediate will be read, or a displacement will be read too.<br>
Most of the meat in the disassembler lies within these functions, they also take care of the prefixes set.<br>
Let's say someone input the disassembler with an operand prefix and a 8bits operation instruction (for instance: 0x66; inc al).<br>
What I am actually trying to say is that only after extracting the operands we can know whether a prefix was used or not.<br>
<br>
5) [Text Formatting]<br>
This is another important step, from all the info we got from the above steps, they are enough to make the instruction representation itself,<br>
but sometimes we still don't have all info required to build an instruction.<br>
So if we fetched a 3DNow! opcode it's time to get its mnemonic, so we know we have to read another byte which will lead us to the complete opcode.<br>
In addition, there are a group of SSE compare instructions which need a two-letters suffix to specify the flags they test, they are kinda similar to 3DNow!<br>
instruction, because only after decoding the whole instruction, you have to read another byte which specifies the flags the instruction should test.<br>
<br>
Anyways, in this step we concatenates all strings together to form the instruction string.<br>
First, we get the instruction's mnemonic from the instruction information structure, taking care of operand size prefix.<br>
There are special instructions, which I call them, Native instructions, that have the same mnemonic no matter of the decoding mode, unless they prefixed.<br>
Such as: pusha, popa, iret. when they are operand size prefixed, they will be suffixed with a letter indicating their operation-size.<br>
For example in 16 and 32 bits decoding: 0x60 is pusha in both cases, but (in 16 bits) 0x66, 0x60 will become pushad...<br>
<br>
There is another exception to mnemonic selection, this happens with the instruction JrCX,<br>
because an operand size prefix affects its offset's size, then an address size prefix affects its mnemonic (actually, its operation size)!<br>
The mnemonic the address size prefix changes is from JCXZ to JECXZ to JRCXZ (depends on the decoding mode, of course).<br>
Did I hear anyone says that he doesn't like hacks?<br>
<br>
If the lock prefix were used and weren't filtered out we would have to prepend the mnemonic with a "LOCK" string.<br>
Or if the rep's prefixes were used and weren't filtered out we would have to prepend the mnemonic with a "REP/REPNZ" string.<br>
<br>
Most of the strings work is done here.<br>
If an instruction weren't found then the first byte is dropped.<br>
I guess that I used the verb 'drop' over and over this documentation already.<br>
What I mean by this is that the first byte of that invalid instruction is output as: "DB 0x??", where ?? is the hex value of that byte,<br>
and we skip only that byte and continue disassembling.<br>
<br>
At last, if we got to an invalid instruction, or there are not enough bytes to read a whole instruction,<br>
or an operand was invalid (for example, some operands require MOD not to be 11, but it read a MOD of 11, it will be an invalid instruction then),<br>
in all these cases the instruction is dropped (DB'ed).<br>
<br>
6) [Hex Dump]<br>
Before we disassemble the instruction itself we try to read all prefixes that precede the instruction itself.<br>
If there are no prefixes, we simply continue on to decode the opcode, etc...<br>
<br>
There are three types of prefixes:<br>
1)Superfluous prefixes -<br>
These prefixes are dropped automatically.<br>
The algorithm I used in order to decide which prefixes are categorized in this type is as follows:<br>
Every prefix can be used once, no matter its order. If that prefix is used again<br>
or another prefix from that same prefix's type is used then all prefixes up to that prefixes are<br>
dropped and treated as extra prefixes.<br>
<br>
Streams and result, by example:<br>
0x66 0x66 0x50: will drop the first 0x66.<br>
0x67 0x66 0x66 0x50: will drop 0x67 and 0x66, because the first 0x66 is canceled, so are the prefixes before.<br>
<br>
0xf0 0xf2 0x50: will drop 0xf0, because 0xf0 and 0xf2 are from the same type.<br>
<br>
0xf0 0xf0 0xf2 0x66 0x2e 0x66 0x67 0x36:<br>
notice it doesn't matter what happens with the first bytes,<br>
because the second segment override cancels the first segment override,<br>
therefore we are left with 0x66 0x67 0x36.<br>
<br>
This algorithm isn't so smart and to be honest, I think that the processor does NOT work the same.<br>
But I thought it's supposed to be enough for a good disassembler.<br>
In the documentation it's not written what happens if a prefix from the same type appears twice or more.<br>
It seems the processor simply ignores most of the extra prefixes, except the lock prefix which renders the instruction invalid.<br>
<br>
I decided on purpose to not drop a lock-prefixed instruction so the user could see it.<br>
This algorithm could be easily changed to something better, but I don't find any reason to change it as for now.<br>
Maybe one should take a look at the open source emulators and see what's going on...<br>
This is the most not-clear subjects in disassemblers and I bet that in processors too, I am open to hear anything about it,<br>
and if there's a good reason, I will change the code. So give it a thought ot two.<br>
<br>
2)Valid prefixes -<br>
These are the prefixes which weren't categorized as extra prefixes.<br>
They are left to be used by the disassembler for the instructions itself.<br>
<br>
3)Unused prefixes -<br>
These are the valid prefixes which weren't used by the disassembler.<br>
We only know which prefixes belong to this category only after we disassembled the instruction itself.<br>
For example:<br>
0x66 0xb0, 0x55 will result in db 0x66; mov al, 0x55<br>
because mov al is a 8 bit operation the operand size prefix can't affect this instruction.<br>
Notice that the prefix itself is valid, but couldn't affect the instruction's behaviour so it wasn't used.<br>
<br>
Unused prefixes have to be sorted by their position before we drop them,<br>
this is because we can't tell their order in advance, that's what the function getunusedprefixeslist responsible for.<br>
Because we want to drop prefixes according to their order we have to sort them out, because when a prefix is counted as valid,<br>
we set a flag which indiciates so (and do some other book keeping), but nothing more. Now, when we know the prefix wasn't used,<br>
we only know that, for instance, only the operand size and segment override prefixes weren't used, but we don't know which we should output first...<br>
<br>
You should pay attention to the way prefixes are dropped, this happens according to their types:<br>
The first type (Superfluous) of prefixes are dropped as a seperated instruction per se.<br>
The second type (valid) prefixes are copied to the beginning of the hex dump buffer, before the instruction's hex itself, of course.<br>
The last type (unused) prefixes are dropped as a seperated instruction, but share the SAME address of the instruction they precede.<br>
<br>
7) [Decoded Instruction]<br>
<br>
- Basic knowledge for this step is how the disassembler's interface is implemented (which can be found below).<br>
<br>
If the instruction doesn't preceded by any prefixes, we use the next available entry in the result array and continue to next instruction.<br>
<br>
On the contrast, if the instruction is prefixed, we use the next available entry in the result array.<br>
(yes you read it alright), this time, if something went wrong we undo that entry insertion.<br>
I gave a thought for this subject, and I understood that most of the prefixes aren't going to do problems,<br>
because afterall a disassembler is there for disassembling code and not garbage/random streams.<br>
Therefore, we give a chance to that instruction and use the next available entry, because we assume it will eventually use it.<br>
But then, if something bad happens - the prefix is unused or dropped - we store that disassemmbled instruction to a temporary memory,<br>
and remove it from the result array, then we insert the dropped prefixes and only then we restore the disassembled instruction back<br>
to the result array.<br>
<br>
This is the familiar do-fail-undo concept -<br>
You know that 99% you should do X, but 1% of the times, you shouldn't,<br>
so you prefer to do it anyways, but if you encounter that 1%, you will fold back and undo it.<br>
<br>
Maybe for some of you it seems a plain concept, but it really boosted the performance of diStorm...<br>
<br>
Another rule with strings is to use the final-destination memory.<br>
That is, avoiding the copying of strings from one location to the other.<br>
After all, the disassembler's sole purpose is to generate text, because we mess with loads of strings,<br>
it is important to not do useless strcpy's when you can do it once, without temporary memory.<br>
Therefore, after retrieving a free entry from the result array I pass that structure to the decoding routine to use.<br>
It might sound unworthy note, but when the only thing you generate is strings and tons of them, it becomes a critical optimization.<br>
<br>
/------------------\<br>
|Program Flow Graph|<br>
\------------------/<br>
I thought this will give you a harsh overview of the disassembler's system and how it works<br>
(I use herein the real functions' names for simplicity):<br>
Unfortunately it's not a graphical layout.<br>
<br>
distormdecode - API - does parameters validations.<br>
internaldecode - Used by the C library API and by Python's extenstion module, implements Decode-Phase #7.<br>
isprefix - Quick way to tell if the next byte in the stream is a prefix.<br>
decodeprefixes - Implements Decode-Phase #6 (the prefixes stuff only).<br>
decodeinst - The disassembler's kernel, disassemble a single instruction.<br>
locateinst - Try to find an SSE instruction (checking for mandatory prefixes) or a normal instruction.<br>
locaterawinst - Finds an instruction(opcode) according to the binary stream itself (doesn't care of prefixes etc).<br>
extractoperand dest, source, op3 - Decode the instruction's operands, start with dest, then source and rarely a 3rd operand.<br>
extractmodrm - Decode the operand according to the ModR/M byte of the instruction.<br>
extractsib - Decode the operand according to the SIB byte of the instruction.<br>
locate3dnowinst - 3DNow! instruction are completed only after the whole instruction was disassembled, time to get their mnemonic.<br>
getunusedprefixeslist - Retrieve the unused prefixes, if any.<br>
## start all over again, until end of stream<br>
<br>
This is the core hierarchy of the kernel of diStorm, this is just so you can quickly start messing with the code,<br>
and when you see it you won't panic. Kernel Panic.<br>
For more information you have the code.<br>
</pre>