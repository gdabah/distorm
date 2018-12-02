#
# diStorm3 (Linux Port)
#

TARGET_BASE	= libdistorm3.so
COBJS	= ../../src/mnemonics.o ../../src/wstring.o ../../src/textdefs.o ../../src/prefix.o ../../src/operands.o ../../src/insts.o ../../src/instructions.o ../../src/distorm.o ../../src/decoder.o
CC	= gcc
CFLAGS	+= -fPIC -O2 -Wall -DSUPPORT_64BIT_OFFSET -DDISTORM_STATIC
LDFLAGS	+= -shared
PREFIX	= /usr/local
# The lib SONAME version:
LIB_S_VERSION = 3
# The lib real version:
LIB_R_VERSION = 3.4.0
LDFLAGS += -Wl,-soname,${TARGET_BASE}.${LIB_S_VERSION}
DESTDIR	=
TARGET_NAME = ${TARGET_BASE}.${LIB_R_VERSION}

all: clib

clean:
	/bin/rm -rf ../../src/*.o ${TARGET_NAME} ../../distorm3.a ./../*.o

clib: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} ${LDFLAGS} -o ${TARGET_NAME}
	ar rs ../../distorm3.a ${COBJS}

install: ${TARGET_NAME}
	install -D -s ${TARGET_NAME} ${DESTDIR}${PREFIX}/lib/${TARGET_NAME}
	ln -sf ${DESTDIR}${PREFIX}/lib/${TARGET_NAME} ${DESTDIR}${PREFIX}/lib/${TARGET_BASE}
	@echo "... running ldconfig might be smart ..."

.c.o:
	${CC} ${CFLAGS} ${VERSION} -c $< -o $@

