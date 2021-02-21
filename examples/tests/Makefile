#
# diStorm (Linux Port) / Demo Application Makefile
#

TARGET	= disasm
CC	= gcc
CFLAGS	= -Wall -O2 -I. -o

all:	torture

disasm: main.cpp ../../distorm3.a
	${CC} ${CFLAGS} ${TARGET} main.cpp ../../distorm3.a

linux_main: linux_main.c ../../distorm3.a
	${CC} ${CFLAGS} ${TARGET} linux_main.c ../../distorm3.a

torture: linux_main
	./ndistest.sh

clean:
	/bin/rm -rf *.o *.asm ${TARGET} 
