I'm going to talk about a few problems that you might encounter since you use a stream disassembler. Some of them are general to disassembling and the other are specific to diStorm.

### Where to find the **next** instruction? ###
The following is an example of a problem which may arise from the stream itself you try to disassemble.

Suppose you try to disassemble the following stream in 32 bits:
```
eb 03 b8 00 00 8b ec 55
```

What diStorm will return is something like this (in Python):
```
(0L, 2L, 'JMP 0x5', 'eb03'),
(2L, 5L, 'MOV EAX, 0xec8b0000', 'b800008bec'),
(7L, 1L, 'PUSH EBP', '55')
```

Where the first integer is the address. So what we are looking at is a JMP instruction that will branch to address 5, but that's the middle of the second instruction. Obviously the code is broken if we follow it an instruction by instruction. What we would really want to see is something like this:

```
(0L, 2L, 'JMP 0x5', 'eb03'),
(5L, 2L, 'MOV EBP, ESP', '8bec'),
(7L, 1L, 'PUSH EBP', '55')
```

Notice the gap between address 3 to 5. Since the JMP instruction skipped them, they are never going to get executed. This is a very basic anti-disassembling/obfuscation technique.

Of course, if you are disassembling legitimate code. A target code that you know in advance that was compiled by a real compiler without any tricky instructions, then you're good to go. But otherwise, you will have to do a recursive disassembling, and use the newer interface of diStorm, more about it described in the end of Flow\_Control\_Support.

### Disassembling the next instruction correctly ###
Let's say you want to disassemble a _big_ block of code, but you also have some memory limitation, which is always true. So every time you will invoke the disassembler you will pass to it the _rest_ of the code block to continue disassembling from and an array to hold the results of the disassembler, which has a predefined size. Now there might be a case where the disassembler filled the array totally but did _not_ finish to disassemble the whole chunk you passed in as an input. Therefore, you will have to invoke the disassembler again (and again) to continue from the last disassembled instruction.

That's why diStorm is really a stream disassembler, so the question at hand is how to **continue** disassembling the stream after each call to the API. Let me show you an example so you understand what I'm talking about.

Suppose you have the following stream,
now imagine that you really have a whole binary in front of you, for the sake of conversation:
```
90 90 90 33 c0 c3
```

If we were calling the distorm\_decode/distorm\_decompose function every time with a single entry to hold the output, we would get a single instruction at a time from the stream, in our case: NOP, NOP, NOP, XOR EAX, EAX, RET.
So there are two things we have to do, we have to know when to stop invoking the disassembler, that is, to know when we reached to the end of the block we wanted to disassemble. And also, we have to know where to continue disassembling the next instruction from. Obviously in a real life application, you will pass an array of, say, 100 entries which will hold the output, but even that is not enough sometimes, depends on the input as well. The point is that you will have to keep the stream synchronized with each call to the API.

The best practices I suggest you should follow is this:
  1. Keep a code-length variable which holds the total size of the block you want to disassemble.
  1. **Always pass the _rest_ of the block, don't cut the code-object into smaller blocks, unless you accurately know the block size is on an instruction boundary, otherwise you may lose synchronization!**
  1. Keep a pointer to the _next_ instruction.
  1. Invoke API, check error code.
  1. Then after every invocation to the API, you will have to update those variables.
  1. If the code-length reached zero, it's an indication you disassembled the whole block, and you can halt.
  1. If code-length is above zero, continue with step 1.

A very good example of how to do it exactly, can be found in the Linux/Win32 sample projects. Learn how their main-loop works, and notice how it synchronizes the variables after every invocation to the API.
Notice that in the samples, we feed the decode API with the total block to decode, that makes things much easier to handle.
http://code.google.com/p/distorm/source/browse/trunk/examples/win32/main.cpp
http://code.google.com/p/distorm/source/browse/trunk/examples/linux/main.c

### Flow control analysis - DF\_RETURN\_FC\_ONLY potential problem ###
To understand this issue please read the former issue first and only then get back here.
Remember that the DF\_RETURN\_FC\_ONLY instructs the disassembler to return only flow-control related instruction, such as: jmp, call, ret, jxx, loop, and the like instructions. The problem with specifying the DF\_RETURN\_FC\_ONLY is that you can lose track of the stream, and get out of synchronization. Let me show you an example:

Suppose you use the decompose API on the following stream, and specifying DF\_RETURN\_FC\_ONLY in the CodeInfo.features field:
```
90, eb, 00, 90, eb, 00, 90, 90
```

You will only get the "JMP 03", "JMP 06" instructions which is good. But again, since the stream is so small there is no problem yet. Let's concentrate on the potential problem here that has good chances to happen in reality. Suppose again that you do the same invocation to the decompose API, but this time you pass only 1 instruction to hold the output. So it will return to you each time with the next flow-control instruction. But now you face a problem, let's try to see what will be the returned output in our case, at first invocation. Probably something like:

"JMP 03" at address 1.
But it's not over, the decomposer will continue disassembling 'till the next JMP instruction, but it will see that it has no room for filling another entry in the output (since in our example we only passed 1 entry for output), and it will return to the caller. All we get then is a single instruction at address 1, which takes 2 bytes. So the next thing we would like to do is calling the decompose API once again to continue from address 3 (following the first JMP instruction), but that is **wrong**! Remember that the disassembler already scanned that instruction, because it really reached the second JMP only to know that it couldn't return it to us as well. What we have to do then is to continue decomposing from that **last** instruction the previous call stopped at, rather than the last returned instruction, you see the difference? This avoids a potential problem of losing synchronization of the stream and not scanning the same instructions twice.

In the former problem we saw that in order to keep on synchronization with the stream, we had to calculate the size of all instructions that the previous invocation returned, then adjust the variables/pointers and invoke the disassembler once again. This technique is not good in our case!

Therefore, another field was added to the CodeInfo structure, which is only used by the decompose API. I'm talking about the 'nextOffset' field. After each invocation to the decompose API this field will be updated to hold the address of the **next** instruction to continue disassembling from, unless it's the end of the stream, which by tracking the code-length you will know so.

So here's a pseudo code snippet of how to use the 'nextOffset' field.
```
CodeInfo ci = {...};
ci.features = DF_RETURN_FC_ONLY.
.
.
.

while (1) {
 distorm_decompose(&ci, ..., &numberOfInstructionsReturned, ...)
 if (numberOfInstructionsReturned == 0) {
  // This does NOT mean we are finished with the stream, it only means that we didn't disassemble any flow-control instruction in the previous call.
 }
 next = ci.nextOffset - codeOffset;
 code += next;
 codeLength -= next;
 codeOffset += next;

 if (codeLength == 0) break; // We are done!
}
```

That's it basically, just make sure you are always synchronized with the stream, and then you're good to go.

### Invalid code that contains only prefixes ###
This is really an edge case. If the stream you try to feed diStorm with has more than 15 bytes of prefixes consecutively, then in reality such a code is not an instruction. The processor will try to fetch prefixes until it sees a byte which is a real opcode, but since the stream has only prefixes, it will reach to the limit of 15 bytes per instruction and then generate a fault. This is why diStorm will return all 15 prefixes as a single instruction each.

However, if you have, say, 14 prefixes and then a NOP, then all the 14 prefixes will be part of the NOP instruction.
```
>>> distorm3.Decode(0, "\x66"*15+"\x90", 1)
[(0L, 1L, 'DB 0x66', '66'), (1L, 1L, 'DB 0x66', '66'), (2L, 1L, 'DB 0x66', '66'),
(3L, 1L, 'DB 0x66', '66'), (4L, 1L, 'DB 0x66', '66'), (5L, 1L, 'DB 0x66', '66'),
(6L, 1L, 'DB 0x66', '66'), (7L, 1L, 'DB 0x66', '66'), (8L, 1L, 'DB 0x66', '66'),
(9L, 1L, 'DB 0x66', '66'), (10L, 1L, 'DB 0x66', '66'), (11L, 1L, 'DB 0x66', '66'),
(12L, 1L, 'DB 0x66', '66'), (13L, 1L, 'DB 0x66', '66'), (14L, 1L, 'DB 0x66', '66'),
(15L, 1L, 'NOP', '90')]
```

Nevertheless, if you ever encounter a prefix as a standalone instruction, you should know that something is wrong with the stream you are trying to decode. It might either be data or a anti-disassembling trick.