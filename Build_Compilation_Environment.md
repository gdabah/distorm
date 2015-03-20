In this page you can find information on how to compile diStorm for various platforms, and change configurations and some more info.

# Distutils #
diStorm can be compiled easily using the distutils of Python.
Something like:
python.exe setup.py install
will compile and install the Python module automatically.
Alternatively, you could build it doing:
python.exe setup.py build
Or one step ahead to install it automatically: python.exe setup.py install

# Compiling the Source Code #
There are a few files that are related to the compilation of the project: distorm.h, config.h and the makefiles.

distorm.h is both used in the compiled library and for the outer projects which use the library. Thus, it's the header file that accompanies the distorm.lib file (or the dynamic/shared library).
It contains the definitions to the APIs of the library, all related flags, structures and helper macros.

The distorm/make supports various platforms for compiling diStorm easily. For now it is, Windows, Linux and Mac. There used to be even DOS and other platforms. It's pretty easy to add support for different platforms. Just play with the makefiles. And you can always take a look at the existing makefiles.

In Visual Studio, you will have to choose a platform (either Win32 or x64) and choose a compilation config, either dll or clib. Then compile the project, and get the resulting file in the distorm's root directory.

In Linux/Mac, you will find a makefile for each. It will create a .SO file. Which you will have to install and then you can easily use diStorm through Python for instance, or use it in the sample projects. If you really wish you can static link diStorm to your poject using the ar command and specify in your project to link against it. Just the usual stuff.

# Important Issues #
## The 'Offset' Type Case ##
config.h has a few important definitions for the library itself, such as the type of the 'offset' field along all the code. That is the type of the virtual address of an instruction. It might be compiled as an 'unsigned long' or as an 'unsigned long long', 32 or 64 bits respectively.

The reason that you can configure the type is because of older compilers support. Or suppose you know that you are going to use diStorm only for disassembling 32 bits code, thus the addressing is 32 bits too, hence there's no reason to use 64 bit offsets. Also, if you were to compile 64 bit integers in a 32 bits compiler, that would require a tiny bit of extra work (simulating 64 bit integers). In fact, the first versions of diStorm supported some DOS compilers which didn't support 64 bit integers.

By default, the type of the 'offset' field is defined as 64 bits integer. The name of the macro that is responsible for this type change is SUPPORT\_64BIT\_OFFSET.

It is turned on by default for Windows, Linux and Mac compilations. However, if you want to compile diStorm for a different platform you will have to pass a macro-define command to the compiler through the command line option using the following: -DSUPPORT\_64BIT\_OFFSET.

If you want to disable 64 bit offset support for some reason, you can either add an #undef preprocessor directive for the macro or just edit the makefile and remove the command line option. Honestly, I don't see any reason to disable it and I urge people to keep the defaults.

## Lib Hell ##
This is a similar problem to DLL hell, that I decided to solve in a specific way using some macro games, keep on reading, then you can check out my blog post which elaborates on the problem.

Supporting this changing integer size for the 'offset' field caused a big problem. Because now the library user has to know how the project was compiled and use the same integer size, otherwise, things will be unmatched and go wrong.

The way I decided to solve this issue was to rename the exported APIs of the library. Suppose we use 64 bit integers, then the Decode function will be named as: 'distorm\_decode64'.

Now, if you're the library user, and you for some reason try to use the 32 bit integers version of the library, you will try to import a function named "distorm\_decode32", which won't be found in the library file, and fail the compilation or dynamic linkage. Then you will know to fix the problem.

For that same reason, I had to declare the APIs with some macros, that will wrap its name and eventually you will be able to use the APIs in their common name: 'distorm\_decode'.
So except from the defining the macro, or commenting it out, the rest is spared from you.

For more info about this naming issue, you can read a blog post I wrote long time a go, [here http://www.ragestorm.net/blogs/?p=22](.md).

### Helper Macros for Compilation ###
Two other important macros are: DISTORM\_STATIC and DISTORM\_DYNAMIC. Their purpose is to aid the compilation to know whether diStorm is being compiled as a static library file or as a dynamic linked library. It instructs distorm.h whether to export the APIs.
For example, you don't want to export the APIs as a library file, because then if another project will link against diStorm in compile-time, it will have the diStorm's APIs exported from the resulted executable object. That's not a big deal, but not professional as well.

And why we need to use DISTORM\_STATIC? That's because if we just compile diStorm as a library, we don't want the APIs to be declared twice (redefined), because the library itself has all APIs as part of the source code, obviously. Again, both the outer projects and diStorm's source code itself share the same header file, distorm.h. Therefore it has to know whether to export the symbols or not...

Eventually, for compiling diStorm as a static library, make sure DISTORM\_STATIC is defined.
For compiling diStorm as a dynamic library or shared object, make sure DISTORM\_DYNAMIC is defined.

Another new macro is DISTORM\_LIGHT, if it is defined, it will _exclude_ all text formatting code from diStorm (the distorm\_decode exports) and leave only the decomposer functionality. This might be useful when one wants to reduce size of the compiled binary. So all menmonics strings are not compiled, etc.

Note that these macros are only used for compiling diStorm source code itself, it doesn't have anything to do with the outer projects which use the compiled library!

## Endianity Issues ##
diStorm was written in such a way that it supports little and big endian machines. Thus, it can run on PowerPC for example, which is a big endian. In order to do that successfully diStorm uses a few macros that are defined in the config.h file, named: RSHORT, RLONG, RULLONG and others. What they actually do is read a specific sized integer from the binary stream and swap their bytes. The effect is that if you try to read an immediate operand which is 4 bytes long, the code will then know to reverse them, so they will be displayed and returned well to the user. It's a very important issue. So actually, that's the only place we need to deal with the edianity, otherwise it is transparent to us.
But how does the compiler knows to which target diStorm is compiled? Well, in the config.h file it tries to guess the endianity upon examining some macros like `_M_IX86`, which means that if the target compilation machine is not x86, then probably it's big endian. This is very fragile, so if you know you want to support ARM or whatever target, that's the way to fix it.

## Aligned Fields in Structures ##
diStorm also supports aligned structures, which means that in some platforms, like ARM, the memory reads/writes of integers must be aligned to an integer size. Therefore all fields in the structures that diStorm uses have to be aligned to an integer size. Therefore structures in distorm.h or instructions.h are not <i>packed</i> as they used to be in early versions of diStorm.

# Python #
As you can see, Python is no longer supported in the compilation itself. It is now an outer part of diStorm. The way Python is supported nowadays is by binding, using the ctypes module. Therefore, you will have to compile diStorm as a shared object, or as a dynamic linked library file, and the Python wrapper will do the rest for you.

It is important to note that if you use Python for x86 system, you will have to compile diStorm for x86 as well. And if you use Python for x64, you will have to compile diStorm for x64 respectively. This is very important, because otherwise, the ctypes module won't be able to load the dynamic library into the process, because of the difference in code size.

For installing the Python module manually, follow these instructions:
  1. Download the diStorm source code, or check out using SVN.
  1. Compile the dynamic library project of diStorm, either .SO or .DLL.
  1. Create a directory for diStorm in the Python\Lib\site-packages directory, name it 'distorm3'.
  1. Copy python/distorm3/init.py and the compiled library to the new directory.

And you're done, launch Python and run "import distorm3".

The Python wrapper has its own interface and it is documented in [Python](Python.md).