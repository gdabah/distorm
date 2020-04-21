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

void strclear_WS(_WString* s);
void chrcat_WS(_WString* s, uint8_t ch);
void strcpylen_WS(_WString* s, const int8_t* buf, unsigned int len);
void strcatlen_WS(_WString* s, const int8_t* buf, unsigned int len);
void strcat_WS(_WString* s, const _WString* s2);

_INLINE_ void strcat_WSR(_WString* str, const _WRegister* reg)
{
	/*
	 * Longest register name is YMM15 - 5 characters,
	 * copy 8 so compiler can do a QWORD move.
	 * We copy nul termination and fix the length, so it's okay to copy more to the output buffer.
	 * There's a sentinel register to make sure we don't read past the end of the registers table.
	 */
	memcpy((int8_t*)&str->p[str->length], (const int8_t*)reg->p, 8);
	str->length += reg->length;
}

/*
* Warning, this macro should be used only when the compiler knows the size of string in advance!
* This macro is used in order to spare the call to strlen when the strings are known already.
* Note: sizeof includes NULL terminated character.
*/
#define strcat_WSN(s, t) strcatlen_WS((s), ((const int8_t*)t), sizeof((t))-1)
#define strcpy_WSN(s, t) strcpylen_WS((s), ((const int8_t*)t), sizeof((t))-1)

#endif /* DISTORM_LIGHT */

#endif /* WSTRING_H */
