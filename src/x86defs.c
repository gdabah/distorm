/*
x86defs.c

Copyright (C) 2003-2009 Gil Dabah, http://ragestorm.net/distorm/
This file is licensed under the GPL license. See the file COPYING.
*/


#include "x86defs.h"
#include "instructions.h"
#include "../mnemonics.h"


_InstInfo II_arpl = {INT_INFO, ISC_INTEGER << 3, OT_REG16, OT_RM16, I_ARPL, INST_MODRM_REQUIRED};
/*
 * MOVSXD is now being decoded properly, definition was incorrect.
 * AMD64: movsxd Gv, Ed
 * Intel: movsxd Gv, Ev
 * Decided on: (OT_REG_FULL, OT_RM_FULL)
 */
_InstInfoEx II_movsxd = {INT_INFO, ISC_INTEGER << 3, OT_RM_FULL, OT_REG_FULL, I_MOVSXD, INST_MODRM_REQUIRED | INST_PRE_REX | INST_64BITS, 0, OT_NONE, OT_NONE, 0, 0};

_InstInfo II_nop = {INT_INFO, ISC_INTEGER << 3, OT_NONE, OT_NONE, I_NOP, INST_FLAGS_NONE};

_InstInfo II_pause = {INT_INFO, ISC_INTEGER << 3, OT_NONE, OT_NONE, I_PAUSE, INST_FLAGS_NONE};
