/*
wstring.c

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#include "wstring.h"

void strclear_WS(_WString* s)
{
	s->p[0] = '\0';
	s->length = 0;
}

void chrcat_WS(_WString* s, uint8_t ch)
{
	s->p[s->length] = ch;
	s->p[s->length + 1] = '\0';
	s->length += 1;
}

void strcpylen_WS(_WString* s, const int8_t* buf, unsigned int len)
{
	s->length = len;
	memcpy((int8_t*)s->p, buf, len + 1);
}

void strcatlen_WS(_WString* s, const int8_t* buf, unsigned int len)
{
	memcpy((int8_t*)&s->p[s->length], buf, len + 1);
	s->length += len;
}

void strcat_WS(_WString* s, const _WString* s2)
{
	memcpy((int8_t*)&s->p[s->length], s2->p, s2->length + 1);
	s->length += s2->length;
}
