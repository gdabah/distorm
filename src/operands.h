/*
operands.h

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#ifndef OPERANDS_H
#define OPERANDS_H

#include "../config.h"

#include "decoder.h"
#include "prefix.h"
#include "instructions.h"

int operands_extract(_CodeInfo* ci, _DecompedInst* di, _InstInfo* ii,
					 _OpType type, _OperandNumberType opNum,
					 unsigned int modrm, _PrefixState* ps, _DecodeType effOpSz,
                     _DecodeType effAdrSz, int* lockableInstruction);

#endif /* OPERANDS_H */
