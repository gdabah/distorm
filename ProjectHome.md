### Introduction ###

Welcome to the diStorm3 binary stream disassembler library project!

<i>No more parsing strings! - diStorm3 is really a decomposer, which means it takes an instruction and returns a binary structure which describes it rather than static text, this is great for advanced binary code analysis.</i>

## <font color='blue'>diStorm3.3 is now available for <i>commercial</i> use <a href='http://ragestorm.net/distorm/'>here</a>.</font> ##

"We benchmarked five popular open-source disassembly libraries and chose diStorm3, which had the best performance (and furthermore, has complete 64-bit support).", July 2014, Quoting David Williams-King in his Thesis about Binary Shuffling.

### Downloads ###
FULL source code with tools and examples, can be downloaded from:
http://ragestorm.net/distorm/distorm3.3-package.zip
MD5:49CE1543E7FD305367107A61D05EEC32

### News ###

**Jan 3rd 2015:**

Finally, lots of new updates!
  1. We support PyPI! Check it out at https://pypi.python.org/pypi/distorm3 You can now use: (python -m) pip install distorm3. Also supports Python 2.x and 3.x!
  1. Some bugs and few instructions were fixed (thanks for submitting guys!)
  1. Added a new macro to check if an instruction is privileged (FLAG\_GET\_PRIVILEGED)
  1. Added new fields to instruction structure - CPU flags affected. They are compatible with EFLAGS, and let you see modified/tested/undefined flags! In addition, the usedRegistersMask is also updated to support all X64 registers (thanks to JonD).
  1. diStorm for C# is now part of diStorm's package, thanks to Dan Shechter. See https://code.google.com/p/distorm/wiki/diStormNet for some help.

**Nov 22nd 2012:**

Ruby Binding (frasm) was updated to support diStorm3.3 by Ron Peleg. https://github.com/rpeleg1970/frasm

**Sep 30th 2012:**

Fixed a text formatting problem with the MOVZX instruction, thanks to Jun Koi for reporting.

**Sep 20th 2012:**

Finally I got to fix the problem with the Python binding. I also had to fix a few other problems. I am testing everything and will upload a new version by tomorrow. Thanks for your patience.

**Jul 29th 2012:**

diStorm version 3.3 is now released.
The structure of a decoded instruction now contains new fields that let one know how the instruction affected the CPU flags (modified, tested, undefined). For more info see the last three fields of the DInst structure inside [DecomposeInterface](DecomposeInterface.md).

Compacted the DB of instructions much more, with another level of shared data among similar instructions...

The Python bindings now support the control flow features that diStorm3 itself support, thanks to Vext01.

**Apr 9th 2012:**

A major release of diStorm3.2 is now available.
Fixed many instructions, either operand accuracy problems or typos in mnemonics. Fixed a few bugs introduced in July 2011. Added new instructions such as: INVPCID, TZCNT, RDxSBASE, WRxSBASE, CVTPS2PH, CVTPH2PS and more.
Added a new compiler directive DISTORM\_LIGHT to compile only distorm\_decompose (no text formatting) to make diStorm smaller in size (should save around 20kb), thanks to Marius Negrutiu of BullGuard.
Fixed the Java wrapper to support latest version.

### Features ###

diStorm is a lightweight, easy-to-use and **fast** decomposer library.

diStorm disassembles instructions in 16, 32 and 64 bit modes.
Supported instruction sets: FPU, MMX, SSE, SSE2, SSE3, SSSE3, SSE4, 3DNow! (w/ extensions), new x86-64 instruction sets, VMX, AMD's SVM and AVX!

The output of new interface of diStorm is a special **structure** that can describe any x86 instruction, this structure can be later formatted into text for display too.

diStorm is written in C, but for rapidly use, diStorm also has wrappers in Python/Ruby/Java and can easily be used in C as well. It is also the fastest disassembler library!

The source code is very clean, readable, portable and platform independent (supports both little and big endianity).
diStorm solely depends on the C library, therefore it can be used in embedded or kernel modules.

Note that diStorm3 is backward compatible with the interface of diStorm64 (however, make sure you use the newest header files).

If you have more ideas, please let me know!

### Documentation ###
Please _read_ the documentation before asking questions, everything you need is pretty much here!
Don't forget that diStorm is open source and you can always take a look to understand how to do one thing or another, but don't do it before you really have to.

For using diStorm in C refer to the [CSample](CSample.md) and it's very important to understand the API too, [SimpleInterface](SimpleInterface.md). However, if you want to use diStorm in Python refer to the [Python](Python.md) example.

Since diStorm3 has a new interface you can learn more about it, starting with the [Showcases](Showcases.md) to get some idea what to expect from using the decompose functionality. Then you better see how the [Structure\_Layout](Structure_Layout.md) is and once you get a clue, continue to the **must read** [DecomposeInterface](DecomposeInterface.md).

If you feel it's enough for you and you want to jump into the water and start coding, here are a few [Tips&Tricks](TipsnTricks.md) that are going to make your life easier while using diStorm.

For advanced users who wish to use diStorm for real flow control analysis, this is your guide: [Flow\_Control\_Support](Flow_Control_Support.md).

As always, since diStorm is a stream disassembler there are some pitfalls that you may encounter, therefore this page [StreamDisassembler](StreamDisassembler.md) might give you some ideas of good practices.

If you wish to compile/build diStorm on your own, on whatever platform, refer to [Build\_Compilation\_Environment](Build_Compilation_Environment.md).

For learning a bit about x86/x64 machine code, see [x86\_x64\_Machine\_Code](x86_x64_Machine_Code.md). And if you want to get a depth knowledge of how the internals of diStorm work, refer to [diStorm\_Internals](diStorm_Internals.md), though it's not up to date with diStorm3, it should give you a good idea how to start hacking your way around.

### About ###
Gil Dabah started this project from scratch in June 2003 for his own fun in his free time. Until today he is still the only guy behind this project. Gil also runs a blog at: http://ragestorm.net/blogs/