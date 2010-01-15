#
# diStorm3 (Mac Port)
#

TARGET	= libdistorm64.dylib
COBJS	= ../../mnemonics.o ../../src/wstring.o ../../src/textdefs.o ../../src/x86defs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/distorm.o ../../src/decoder.o
PYOBJS	= ../../src/x86defs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/pydistorm.o ../../src/decoder.o
CC	= gcc
CFLAGS	= -O2 -Wall -fPIC -DSUPPORT_64BIT_OFFSET -D_DLL -I/System/Library/Frameworks/Python.framework/Headers

all: clib py

clean:
	/bin/rm -rf ../../src/*.o ${TARGET} ../../distorm64.dylib

clib: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -fPIC -dynamiclib -o ${TARGET}
	ar rs ../../distorm64.a ${COBJS}

py: ${PYOBJS}
	${CC} ${CFLAGS} ${VERSION} ${PYOBJS} -fPIC -dynamiclib -o ${TARGET} -lpython
.c.o:
	${CC} ${CFLAGS} ${VERSION} -c $< -o $@

