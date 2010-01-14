#
# diStorm (Linux Port) / Demo Application Makefile
#

TARGET	= disasm
CC	= gcc
CFLAGS	= -Wall -O2 -o

all:	disasm

disasm:
	${CC} ${CFLAGS} ${TARGET} main.c ../distorm64.a

clean:
	/bin/rm -rf *.o ${TARGET} 
