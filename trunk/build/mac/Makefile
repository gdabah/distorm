#
# diStorm3 (Mac Port)
#

TARGET	= libdistorm3.dylib
COBJS	= ../../mnemonics.o ../../src/wstring.o ../../src/textdefs.o ../../src/x86defs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/distorm.o ../../src/decoder.o
CC	= gcc
CFLAGS	= -O2 -Wall -fPIC -DSUPPORT_64BIT_OFFSET -D_DLL

all: clib

clean:
	/bin/rm -rf ../../src/*.o ${TARGET} ../../libdistorm3.dylib ../../distorm3.a

clib: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -fPIC -dynamiclib -o ${TARGET}
	ar rs ../../distorm3.a ${COBJS}

.c.o:
	${CC} ${CFLAGS} ${VERSION} -c $< -o $@