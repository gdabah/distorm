This page covers the advanced functionality that the new interface of diStorm3 supplies. This is the time to say that diStorm, as a stream disassembler, doesn't do the flow control analysis work for you, but it will help you do that more easily.

The Decompose function requires the caller to pass a CodeInfo structure. In that structure there are all the parameters you pass normally to the Decode function and in addition there's a new parameter (or field) named 'features'. This is a flags parameter, so you can pass along a few flags together to control the way diStorm returns the disassembled instructions.

Let's list the possible decode flags (some of them are not related to flow control though):
Note that you can combine any of the flags below, except DF\_MAXIMUM\_ADDR16 with DF\_MAXIMUM\_ADDR32.

<b>DF_NONE</b>
  * If you don't want to use this stuff, just set this flag, and the Decompose will work normally. That is, like the Decode function, but return structure output.

<b>DF_MAXIMUM_ADDR16</b>
  * If you decode 16 bits code, you can limit the addresses range to 16 bits.
  * For instance, if you have a piece of code that JMPs backwards to a negative offset, instead of getting something like 0xfffffffff, you will get 0xffff. Or only the low 16 bits of the address.
  * This is mostly good for display.

<b>DF_MAXIMUM_ADDR32</b>
  * Nowadays that we got 64 bits decoding as well, we sometimes want to limit addresses to 32 bits. Works like DF\_MAXIMUM\_ADDR16 but for 32 bits.
  * The truth is that the decoder will store the instructions using full 64 bit addresses, but only the distorm\_format function will cut the addresses.

<b>DF_RETURN_FC_ONLY</b>
  * This is the most important flag IMHO. What it really does is telling the Decompose function that it should return only flow control instructions back to the caller, and filter the rest of them.
  * Effectively, you will get only the branch and similar instructions, making it easier to track flow control code.
  * If you want to use this flag you have to be careful because there is some problem lurking around the corner. You **have** to read this [StreamDisassembler](StreamDisassembler.md). Notice that the "instruction-count" that the decompose returns, is _not_ the same as the "decoded-instructions-count" and this is why you can lose synchronization of the stream and decode the code just wrong.

<b>DF_STOP_ON_CALL</b>
  * Makes the Decompose function return to the caller when a CALL/FAR instruction was decoded.

<b>DF_STOP_ON_RET</b>
  * Makes the Decompose function return to the caller when a RET/IRET/RETF instruction was decoded.

<b>DF_STOP_ON_SYS</b>
  * Makes the Decompose function return to the caller when a SYSENTER/SYSEXIT/SYSCALL/SYSRET instruction was decoded.

<b>DF_STOP_ON_UNC_BRANCH</b>
  * Makes the Decompose function return to the caller when a JMP/FAR instruction was decoded.

<b>DF_STOP_ON_CND_BRANCH</b>
  * Makes the Decompose function return to the caller when a conditional branch (Jxx, JCxx, LoopXX) instruction was decoded.

<b>DF_STOP_ON_INT</b>
  * Makes the Decompose function return to the caller when an interrupt instruction (INT, INTO, INT1, INT3, UD2) was decoded.

<b>DF_STOP_ON_CMOV</b>
  * Makes the Decompose function return to the caller when any of the CMOVxx instruction was decoded.

<b>DF_STOP_ON_FLOW_CONTROL</b>
  * Makes the Decompose function return to the caller when any of the above instructions are decoded.


---

Note that most of the flags are telling the Decompose function when to **stop** decoding. However, the only filter is the <i>DF_RETURN_FC_ONLY</i> flag. Currently, there's no other way to filter all instruction except a specific type of instructions.

Suppose you want to get the target address of a call instruction in a specific code block:
```
mov eax, 1
push eax
push 0
lea eax, [ebp+10]
push eax
call some_function
```

You can call the Decompose function with the DF\_STOP\_ON\_CALL and DF\_RETURN\_FC\_ONLY. Which will return only the CALL instruction, in this case(!). This is quiet good if you know there are no flow control instructions in the stream, except the one you're interested in.
So basically what you can do next, is to check that the <i>last</i> instruction in the results array, is the call instruction.
There are two ways to check for that, either by comparing the 'opcode' field to I\_CALL, or by checking the 'meta' field with the helper macro META\_GET\_FC and compare the result to FC\_CALL. Then once you're sure it's the instruction you were looking for you can get the target address, by using another helper macro, INSTRUCTION\_GET\_TARGET. So eventually you will get, by our example, the address of 'some\_function'.

That's why also the meta information of the instruction is very important to flow control, so you know whether the instruction you're just examining is flow control related. The META\_GET\_FC returns one of the following values:
FC\_NONE, FC\_CALL, FC\_RET, FC\_SYS, FC\_UNC\_BRANCH, FC\_CND\_BRANCH, FC\_INT and FC\_CMOV.
They are self explanatory and notice that there FC\_UNC\_BRANCH and FC\_CND\_BRANCH, so you can easily distinguish between the two cases of <i>always-branch</i> to <i>conditional-branch</i>.

Suppose you want to follow the flow control of a function starting from its start address, you will want to stop on every flow control instruction and examine its type. I'm not going to talk about an algorithm for doing that, it's out of the scoop of this wiki page. But here are a few tips for using diStorm for that goal:
  * When analyzing flow control, we don't care about the data flow, unless it affects a conditional branch.
  * So the flags you probably want to pass to the Decompose function are DF\_RETURN\_FC\_ONLY and DF\_STOP\_ON\_FLOW\_CONTROL.
  * The merge of the two flags together is pretty strong, because you are left with the flow control instructions only. Then later if you want, you can get the basic blocks, etc.
  * Calling the Decompose function in a loop, until you have exhausted the whole function, by reaching all RET instructions. (It's up to you to know when you scanned the whole function, probably you are going to need a table of addresses you already visited, etc).
  * Everytime the Decompose function returns, it means you got a flow control related instruction in the result. As a matter of fact, you can supply a single _DInst structure rather than an array, because it will stop on the first flow control instruction it encounters.
  * That's why you should update the address when calling the Decompose again the next time, so it_<i>continues</i> from the next instruction that wasn't disassembled yet. Something simple like updating the CodeInfo fields, to start from the returned instruction address + its size.
  * Now you need to decide what to do with the instruction you got returned, you will have to check whether its a conditional branch or not. Actually there's more to it, let's see why. If the instruction you got is a CALL instruction, you want to queue the next instruction's address and continue with its target address. If it's a JMP instruction, you just continue with its target address. And if it's a conditional branch, you will queue the next instruction's address and continue with its target address. Then the logic of the analyzer would be to pop an address from the queue and continue there.
  * Of course instead of testing the opcode field against all conditional branch instruction, just use the meta information for FC\_CND\_BRANCH.