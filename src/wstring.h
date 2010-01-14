/*
wstring.h

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#ifndef WSTRING_H
#define WSTRING_H

#include "../config.h"

void strclear_WS(_WString* s);
void chrcat_WS(_WString* s, uint8_t ch);
void strcpylen_WS(_WString* s, const int8_t* buf, unsigned int len);
void strcatlen_WS(_WString* s, const int8_t* buf, unsigned int len);
void strcat_WS(_WString* s, const _WString* s2);

/*
* Warning, this macro should be used only when the compiler knows the size of string in advance!
* This macro is used in order to spare the call to strlen when the strings are known already.
* Note: sizeof includes NULL terminated character.
*/
#define strcat_WSN(s, t) strcatlen_WS((s), ((const int8_t*)t), sizeof((t))-1)
#define strcpy_WSN(s, t) strcpylen_WS((s), ((const int8_t*)t), sizeof((t))-1)

#endif /* WSTRING_H */
