#
# diStorm64 (Linux Port)
#

TARGET	= libdistorm64.so
COBJS	= ../../mnemonics.o ../../src/wstring.o ../../src/textdefs.o ../../src/x86defs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/distorm.o ../../src/decoder.o
CC	= gcc
CFLAGS	= -O2 -Wall -DSUPPORT_64BIT_OFFSET -D_LIB

all: clib

clean:
	/bin/rm -rf ../../src/*.o ${TARGET} ../../distorm64.a ../../mnemonics.o

clib: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -shared -o ${TARGET} -pg
	ar rs ../../distorm64.a ${COBJS}

install: libdistorm64.so
	install -s ${TARGET} /usr/local/lib
	@echo "... running ldconfig might be smart ..."

.c.o:
	${CC} ${CFLAGS} ${VERSION} -p -c $< -o $@ -pg

