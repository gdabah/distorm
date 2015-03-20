I'm going to show a few practical ways to use the new Decompose API.

First of all, you can call distorm\_decompose and test the return value for DECRES\_INPUTERR. Because the rest of the return code mean that you have to read from the instructions array you supplied anyway. To be honest, you can even drop the test for DECRES\_INPUTERR, only if you know that you are calling the API <i>well</i>. But it can never harm, obviously.

The next thing after calling distorm\_decompose would be to check the number of instructions returned, this can now probably answer your question on why it's not a must to check the returned error code. So if the instructions count is zero, you then should know that something is wrong. It's important to understand that diStorm will return instructions even if they are invalid. Suppose you have a stream of one byte: "b8", that's the opcode of a ` "MOV EAX, <IMM>" ` instruction, but as you see, we don't have the immediate in the stream. So diStorm will return only a single instruction which will indicate the instruction wasn't decoded well. But the point is that it will return an instruction nevertheless. So probably if no instructions were returned, you passed a zero length stream, or reached the end of the stream.

After checking the instructions count, when touching each decomposed-instruction structure, make sure you validate the instruction was decoded well by examining its flags, comparing it to FLAG\_NOT\_DECODABLE.

A sample code would be:
```
unsigned char my_code_stream[] = {0x90, 0x90, 0x33, 0xc0, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xcc};
_DInst result[15];
unsigned int instructions_count = 0;
_DecodedInst inst;

_CodeInfo ci = {0};
ci.code = my_code_stream;
ci.codeLen = sizeof(my_code_stream);
ci.dt = Decode32Bits;
ci.codeOffset = 0x100000;

distorm_decompose(&ci, result, sizeof(result)/sizeof(result[0]), &instructions_count);

// well, if instruction_count == 0, we won't enter the loop.
for (unsigned int i = 0; i < instructions_count; i++) {
 if (result[i].flags == FLAG_NOT_DECODABLE) {
  // handle instruction error!
  break;
 }
 distorm_format(&ci, &result[i], &inst);
 printf("%s %s\n", inst.mnemonic.p, inst.operands.p);
}
```

The sample is a bit dumb, because there's no point in calling the decompose API and then immediately formatting the string into text, we could have used the decode API from the first place anyway.

Let's move on to more interesting issues.
Finding whether an instruction is a CALL.
```
if (META_GET_FC(result[i].meta) == FC_CALL)
```

In order to find whether an instruction is a JMP or RET, use FC\_BRANCH, FC\_RET, etc.
However note that FC\_CALL and FC\_BRANCH might include the FAR variation of the instruction, if that's a problem with you, here's another way.

Note that the advantage of using the meta data of the instruction saves you the look up table for multiple instructions, let me show you.

Suppose you want to find all <i>conditional</i> branch instructions, you can easily use the FC\_COND\_BRANCH.
But what happens if you want to find all arithmetic instruction?

Then you will have to do the following switch cases:
```
switch (result[i].opcode)
{
 case I_XOR:
 case I_OR:
 case I_AND:
  // Instruction is arithmetic.
 break;
}
```

The same for finding if an instruction is doing the "addtract" operation:
I\_INC, I\_ADD, I\_ADC.

If you want to get crazier you can even check I\_LEA and then check its operands.

I guess you get the idea of the opcode tests by now, for the full opcode list check the [Menmonics](http://code.google.com/p/distorm/source/browse/trunk/mnemonics.h) file.

So suppose we were looking for branch instruction like JMPs or CALLs, now we would like to know the target address, right?

There is a helper macro to do just that.
But before we will be using it, we have to make sure the helper macro can aid us, it really depends on the operands of the instruction. If there's a ` CALL [EAX] ` then the helper macro won't be able to supply an absolute address, so no point using it. Therefore first thing we will have to do before using it is testing the operands type:
```
_OffsetType absolute_target_address = 0;
if (result[i].operands[0] == O_PC) {
 absolute_target_address = INSTRUCTION_GET_TARGET(&result[i]);
}
```

The O\_PC operand type indicates the operand of the instruction is surely a branch relative offset.

If we know we got a CALL instruction but its type isn't O\_PC, only then we can conclude that the operand is something more complex than a simple offset. Something like ` CALL [ECX + 4] `, which is O\_SMEM.

Worth to know that the O\_PC must be the first operand if it's ever used by the instruction, this is due to the Instruction Set Architecture or ISA in short.

It's very sexy in X64 to use the RIP-relative operands. This way you can achieve Position Independent Code, rather than doing the old trick of ` CALL $+5; POP EAX `. So suppose we want to find where the RIP-relative instruction points to, we will have to first find whether the instruction uses the RIP register and only then we will continue to the calculation.

Since the RIP register can be used in any of the operands, we will have to check for them all.

The following snippet is fine:
```
_DInst di = &result[i];
if ( ((di->ops[0].type == O_SMEM) && (di->ops[0].index == R_RIP)) ||
     ((di->ops[1].type == O_SMEM) && (di->ops[1].index == R_RIP)) )
{
     absolute_target_address = (_OffsetType)(di->addr + di->disp + di->size);
}
```

Now you can see why a flag could be handy, because for calculating the target address we don't need to access any of the operands directly. Therefore I recently added a new flag called FLAG\_RIP\_RELATIVE. And it should be used in the following way:
```
if (result[i].flags & FLAG_RIP_RELATIVE)
{
 absolute_target_address = INSTRUCTION_GET_RIP_TARGET(&result[i]);
}
```
And scanning the operands is eliminated.

Now to another issue, getting a bit of meta information about the displacement. The displacement is the offset which is used when referring to another register, such as [+ OFF](REG.md). Note that it has to be an indirection.

Suppose we want to know whether this displacement is either negative or positive, the way to do that is as such:
```
if (result[i].dispSize != 0) { // The only true indication for a used displacement, however the disp itself can be zero. 
 if (result[i].disp < 0) // Negative disp!
 else if (result[i] > 0) // Positive disp!
}
```

Notice how I am avoiding the disp == 0, this is important since some registers have the implied displacement of zero. For example, the rBP register always has this hidden displacement, so when you do ` "MOV EAX, [EBP]"`, the Assembler really generates: ` "MOV EAX, [EBP+0]" `. Again, this is because of the ISA.

About the displacement size and immediate size, sometimes you don't really have to check them. Because both the displacement and the immediate are <b>sign extended</b>. I see people testing the size, and then accessing the imm union according to the size of the immediate, this is a big waste. Don't access the imm by its union, unless you have a good reason to. It will make your code more readable and easier to write!

Another example for finding all instructions that touch the stack:
```
switch (result[i].opcode)
{
 case I_PUSH:
 case I_PUSHA:
 case I_PUSHF:
 case I_ENTER:
 case I_LEAVE:
 case I_POPF:
 case I_POPA:
 case I_POP:
  // Stack related instructions.
 break;
}
```

Of course it's worth to do another test for all instructions which touch the ESP or the EBP registers as well:
```
int is_stack_related_instruction(_DInst* di)
{
 // Assumes di is a valid instruction.
 for (int i = 0; i < OPERAND_NO; i++) {
  if ((di->operands[i].type == O_REG) || (di->operands[i].type == O_SMEM) || (di->operands[i].type == O_MEM)) {
   if ((di->operands[i].index == R_EBP) || (di->operands[i].index == R_ESP)) return 1; // yey
  } else continue; // Skip operand.
 }
 
 // Also make sure the base register of O_MEM is either EBP or ESP.
 // it's safe to access it even though we don't certainly know there's an O_MEM operand, since 'base' always gets cleared.
 if ((di->base == R_EBP) || (di->base == R_ESP)) return 1;

 return 0;
}
```

This also BEGS a 'registersUsed' field in the decomposed instruction structure for quickly checking for a used register. So I decided added it later on. The new code would be something like this.

```
int is_stack_related_instruction(_DInst* di)
{
 return ((di->usedRegistersMask & (RM_SP | RM_BP)) != 0);
}
```
Compare for yourself! You see? One comparison operator and you're done. This will work for both 32 and 64 bits at once, unlike the former snippet which supports only 32 bits.
And note that in order to know whether the instruction is 'stack-related' we don't really want to know what it does, and which operand describe what, or scan its operands.
We will merely have to check the registers-mask. Splendid. I have to admit that the registers-mask is a bit limited, because it doesn't support <i>all</i> registers, but still, a good start.

Some instructions like PUSHA or PUSHF don't have any operands, how can we determine the size of operation, whether PUSHF, for instance, pushes the 32 bit flags register or the 16 bits flags register? Fortunately, diStorm does this for you, you don't have to look for prefix bytes in the stream of the instruction itself.

There we go:
```
if (result[i].opcode == I_PUSHF) {
 _DecodeType d = (_DecodeType)FLAG_GET_OPSIZE(result[i].flags);
 if (d == Deocde16Bits) ...
 else if (d == Decode32Bits) ...
 else /* Decode64Bits */ ...
}
```
As simple as that. The OPSIZE is the "operation size" of the instruction, its exactly what you need in order to know the size of the flags register in our case.

That's it for now.
if you have any other tricks, or have questions feel free to ask me.
Good luck