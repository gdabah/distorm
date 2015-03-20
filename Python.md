## Python ##
list Decode(long offset, string code, int mode)

Input:

| Argument Name | Description |
|:--------------|:------------|
|offset| **Virtual** address of the code itself (as in origin) |
|code| Buffer of the binary code |
|mode| Decode16Bits - 80286 decoding, Decode32Bits - IA-32 decoding, Decode64Bits - AMD64 decoding|


Return:
list - List of tuples with the disassembled instructions,
> each tuple consists of offset, size, mnemonic and hex strings per instruction

**Note:** The first argument _offset_ is the virtual address of the _code_ block. It is **not** an offset inside _code_! It is similar to the [[org](org.md)] directive of Assemblers.

### Sample 1: ###
```
from distorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
l = Decode(0x100, open("file.com", "rb").read(), Decode16Bits)
for i in l:
 print "0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2])
```

### Sample 2: ###
```
>>>Decode(0x400000, 'b800000000'.decode('hex'), Decode32Bits)
[(4194304L, 5L, 'MOV EAX, 0x0', 'b800000000')]
```

### Sample 3: ###
Check out the Python's sample that comes with diStorm: http://code.google.com/p/distorm/source/browse/trunk/python/distorm3/sample.py