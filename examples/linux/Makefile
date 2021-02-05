#
# diStorm (Linux Port) / Demo Application Makefile
#

TARGET	= disasm
CC	= gcc
CFLAGS	= -Wall -O2 -o

all:	disasm

disasm: main.c ../../distorm3.a
	${CC} ${CFLAGS} ${TARGET} main.c ../../distorm3.a

distorm:
	cd ../../make/linux && make

torture: disasm
	./disasm.exe -b64 torture.bin 0x140016124

clean:
	/bin/rm -rf *.o ${TARGET} 
