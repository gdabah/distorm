/*
insts.h

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#ifndef INSTS_H
#define INSTS_H

#include "instructions.h"

/* Root Trie DB */
extern _InstNode Instructions;
/* 3DNow! Trie DB */
extern _InstNode Table_0F_0F;
/* AVX related: */
extern _InstNode Table_0F, Table_0F_38, Table_0F_3A;

#endif /* INSTS_H */
