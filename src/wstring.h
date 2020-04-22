/*
wstring.h

diStorm3 - Powerful disassembler for X86/AMD64
http://ragestorm.net/distorm/
distorm at gmail dot com
Copyright (C) 2003-2020 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/


#ifndef WSTRING_H
#define WSTRING_H

#include "config.h"
#include "../include/mnemonics.h"

#ifndef DISTORM_LIGHT

_INLINE_ void strcat_WSR(unsigned char** str, const _WRegister* reg)
{
	/*
	 * Longest register name is YMM15 - 5 characters,
	 * Copy 8 so compiler can do a QWORD move.
	 * We copy nul termination and fix the length, so it's okay to copy more to the output buffer.
	 * There's a sentinel register to make sure we don't read past the end of the registers table.
	 */
	memcpy((int8_t*)*str, (const int8_t*)reg->p, 8);
	*str += reg->length;
}

_INLINE_ void strfinalize_WS(_WString* s, unsigned char* endStrPtr)
{
	*endStrPtr = 0;
	s->length = (unsigned int)((size_t)endStrPtr - (size_t)s->p);
}

_INLINE_ void chrcat_WS(unsigned char** s, uint8_t ch)
{
	**s = ch;
	*s += 1;
}

_INLINE_ void strcat_WS(unsigned char** s, const int8_t* buf, unsigned int len)
{
	memcpy((int8_t*)*s, buf, len);
	*s += len;
}


/*
* Warning, this macro should be used only when the compiler knows the size of string in advance!
* This macro is used in order to spare the call to strlen when the strings are known already.
* Note: sizeof includes NULL terminated character.
*/
#define strcat_WSN(s, t) strcat_WS((s), ((const int8_t*)t), sizeof((t))-1)

#endif /* DISTORM_LIGHT */

#endif /* WSTRING_H */
