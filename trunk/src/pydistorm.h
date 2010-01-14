/*
pydistorm.h

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#ifndef PYDISTORM_H
#define PYDISTORM_H

#ifdef SUPPORT_64BIT_OFFSET
/*
 * PyArg_ParseTuple/Py_BuildValue uses a format string in order to parse/build the offset.
 * type: int 64
 */
	#define _PY_OFF_INT_SIZE_ "K"
#else
	#define _PY_OFF_INT_SIZE_ "k"
#endif

#include "decoder.h"

#include <Python.h>

PyObject* distorm_Decompose(PyObject* pSelf, PyObject* pArgs);

char distorm_Decompose_DOCSTR[] =
"Disassemble a given buffer to a list of structures that each describes an instruction.\r\n"
#ifdef SUPPORT_64BIT_OFFSET
	"Decompose(INT64 offset, string code, int type)\r\n"
#else
	"Decompose(unsigned long offset, string code, int type)\r\n"
#endif
"type:\r\n"
"	Decode16Bits - 16 bits decoding.\r\n"
"	Decode32Bits - 32 bits decoding.\r\n"
"	Decode64Bits - AMD64 decoding.\r\n"
"Returns a list of decomposed objects. Refer to diStorm3 documentation for learning how to use it.\r\n";

static PyMethodDef distormModulebMethods[] = {
    {"Decode", distorm_Decompose, METH_VARARGS, distorm_Decompose_DOCSTR},
    {NULL, NULL, 0, NULL}
};

#endif /* PYDISTORM_H */

