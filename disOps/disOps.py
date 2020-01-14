#
# disOps.py v 1.0.0
#
# Copyright (C) 2003-2018 Gil Dabah, http://ragestorm.net/distorm/
#
# disOps is a part of the diStorm project, but can be used for anything.
# The generated output is tightly coupled with diStorm data structures which can be found at instructions.h.
# The code in diStorm that actually walks these structures is found at instructions.c.
#
# Since the DB was built purposely for diStorm, there are some
# Known issues:
#   1. ARPL/MOVSXD information in DB is stored as ARPL.
#      Since ARPL and MOVSXD share the same opcode this DB doesn't support this mix.
#      Therefore, if you use this DB for x64 instructions, you have to take care of this one.
#
#   2. SSE CMP pseudo instructions have the DEFAULT suffix letters of its type in the second mnemonic,
#      the third operand, Imm8 which is responsible for determining the suffix,
#      doesn't appear in the operands list but rather an InstFlag.PSEUDO_OPCODE implies this behavior.
#
#   3. The WAIT instruction is a bit problematic from a static DB point of view, read the comments in init_FPU in x86sets.py.
#
#   4. The OpLen.OL_33, [0x66, 0x0f, 0x78, 0x0], ["EXTRQ"] is very problematic as well.
#      Since there's another 8 group table after the 0x78 byte in this case, but it's already a Prefixed table.
#      Therefore, we will handle it as a normal 0x78 instruction with a mandatory prefix of 0x66.
#      But the REG (=0) field of the ModRM byte will be checked in the decoder by a flag that states so.
#      Otherwise, another normal table after Prefixed table really complicates matters,
#      and doesn't worth the hassle for one exceptional instruction.
#
#   5. The NOP (0x90) instruction is really set in the DB as xchg rAX, rAX. Rather than true NOP, this is because of x64 behavior.
#      Hence, it will be decided in runtime when decoding streams according to the mode.
#
#   6. The PAUSE (0xf3, 0x90) instruction isn't found in the DB, it will be returned directly by diStorm.
#      This is because the 0xf3 in this case is not a mandatory prefix, and we don't want it to be built as part of a prefixed table.
#
#   7. The IO String instructions don't have explicit form and they don't support segments.
#      It's up to diStorm to decide what to do with the operands and which segment is default and overrided.
#
#   8. Since opcodeId is an offset into the mnemonics table, the psuedo compare mnemonics needs a helper table to fix the offset.
#      Psuedo compare instructions work in such a way that only the first instruction is defined in the DB.
#      The rest are found using the third operand (that's why they are psuedo).
#
# To maximize the usage of this DB, one should learn the documentation of diStorm regarding the InstFlag and Operands Types.
#

import re
import time
import functools
import os
import x86sets
import x86db
import x86generator

# Work with multi line and dot-all.
reFlags = re.M | re.S

def CreateMnemonicsC(mnemonicsIds):
	""" Create the opcodes arrays for C header files. """
	opsEnum = "typedef enum {\n\tI_UNDEFINED = 0, "
	pos = 0
	l2 = sorted(mnemonicsIds.keys())
	for i in l2:
		s = "I_%s = %d" % (i.replace(" ", "_").replace(",", ""), mnemonicsIds[i])
		if i != l2[-1]:
			s += ","
		pos += len(s)
		if pos >= 70:
			s += "\n\t"
			pos = 0
		elif i != l2[-1]:
			s += " "
		opsEnum += s
	opsEnum += "\n} _InstructionType;"

	# Mnemonics are sorted by insertion order. (Psuedo mnemonics depend on this!)
	# NOTE: EXTRA BACKSLASHES FORE RE.SUB !!!
	s = "const unsigned char _MNEMONICS[] =\n\"\\\\x09\" \"UNDEFINED\\\\0\" "
	l = list(zip(mnemonicsIds.keys(), mnemonicsIds.values()))
	l = sorted(l, key=functools.cmp_to_key(lambda x, y: x[1] - y[1]))
	for i in l:
		s += "\"\\\\x%02x\" \"%s\\\\0\" " % (len(i[0]), i[0])
		if len(s) - s.rfind("\n") >= 76:
			s += "\\\\\n"
	s = s[:-1] + ";" # Ignore last space.
	# Return enum & mnemonics.
	return (opsEnum, s)

def CreateMnemonicsPython(mnemonicsIds):
	""" Create the opcodes dictionary for Python. """
	s = "Mnemonics = {\n"
	for i in mnemonicsIds:
		s += "0x%x: \"%s\", " % (mnemonicsIds[i], i)
		if len(s) - s.rfind("\n") >= 76:
			s = s[:-1] + "\n"
	# Fix ending of the block.
	s = s[:-2] # Remote last comma/space we always add for the last line.
	if s[-1] != "\n":
		s += "\n"
	# Return mnemonics dictionary only.
	return s + "}"

def CreateMnemonicsJava(mnemonicsIds):
	""" Create the opcodes dictionary/enum for Java. """
	s = "public enum OpcodeEnum {\n\tUNDEFINED, "
	for i in mnemonicsIds:
		s += "%s, " % (i.replace(" ", "_").replace(",", ""))
		if len(s) - s.rfind("\n") >= 76:
			s = s[:-1] + "\n\t"
	# Fix ending of the block.
	s = s[:-2] # Remote last comma/space we always add for the last line.
	if s[-1] != "\n":
		s += "\n"
	opsEnum = s + "}"
	s = "static {\n\t\tmOpcodes.put(0, OpcodeEnum.UNDEFINED);\n"
	for i in mnemonicsIds:
		s += "\t\tmOpcodes.put(0x%x, OpcodeEnum.%s);\n" % (mnemonicsIds[i], i.replace(" ", "_").replace(",", ""))
	s += "\t}"
	# Return enum & mnemonics.
	return (opsEnum, s)

def WriteMnemonicsC(mnemonicsIds):
	""" Write the enum of opcods and their corresponding mnemonics to the C files. """
	path = os.path.join("..", "include", "mnemonics.h")
	print("- Try rewriting mnemonics for %s." % path)
	e, m = CreateMnemonicsC(mnemonicsIds)
	old = open(path, "r").read()
	rePattern = "typedef.{5,20}I_UNDEFINED.*?_InstructionType\;"
	if re.compile(rePattern, reFlags).search(old) == None:
		raise Exception("Couldn't find matching mnemonics enum block for substitution in " + path)
	new = re.sub(rePattern, e, old, 1, reFlags)
	open(path, "w").write(new)
	print("Succeeded")

	path = os.path.join("..", "src", "mnemonics.c")
	print("- Try rewriting mnemonics for %s." % path)
	old = open(path, "r").read()
	rePattern = "const unsigned char _MNEMONICS\[\] =.*?;"
	if re.compile(rePattern, reFlags).search(old) == None:
		raise Exception("Couldn't find matching mnemonics text block for substitution in " + path)
	new = re.sub(rePattern, m, old, 1, reFlags)
	open(path, "w").write(new)
	print("Succeeded")

def WriteMnemonicsPython(mnemonicsIds):
	""" Write the dictionary of opcods to the python module. """
	#
	# Fix Python dictionary inside distorm3/_generated.py.
	#
	path = os.path.join("..", "python", "distorm3", "_generated.py")
	print("- Try rewriting mnemonics for %s." % path)
	d = CreateMnemonicsPython(mnemonicsIds)
	old = open(path, "r").read()
	rePattern = "Mnemonics = \{.*?\}"
	if re.compile(rePattern, reFlags).search(old) == None:
		raise Exception("Couldn't find matching mnemonics dictionary for substitution in " + path)
	new = re.sub(rePattern, d, old, 1, reFlags)
	open(path, "w").write(new)
	print("Succeeded")

def WriteMnemonicsJava(mnemonicsIds):
	""" Write the enum of opcods and their corresponding mnemonics to the Java files. """
	#
	# Fix Java enum and mnemonics arrays
	#
	path = os.path.join("..", "examples", "java", "distorm", "src", "diStorm3", "OpcodeEnum.java")
	print("- Try rewriting mnemonics for %s." % path)
	e, m = CreateMnemonicsJava(mnemonicsIds)
	old = open(path, "r").read()
	rePattern = "public enum OpcodeEnum \{.*?}"
	if re.compile(rePattern, reFlags).search(old) == None:
		raise Exception("Couldn't find matching mnemonics enum block for substitution in " + path)
	new = re.sub(rePattern, e, old, 1, reFlags)
	open(path, "w").write(new)
	print("Succeeded")

	path = os.path.join("..", "examples", "java", "distorm", "src", "diStorm3", "Opcodes.java")
	print("- Try rewriting mnemonics for %s." % path)
	old = open(path, "r").read()
	rePattern = "static \{.*?}"
	if re.compile(rePattern, reFlags).search(old) == None:
		raise Exception("Couldn't find matching mnemonics text block for substitution in " + path)
	new = re.sub(rePattern, m, old, 1, reFlags)
	open(path, "w").write(new)
	print("Succeeded")

def WriteInstsC(lists):
	""" Write the tables of the instructions in the C source code. """
	path = os.path.join("..", "src", "insts.c")
	print("- Try rewriting instructions for %s." % path)
	old = open(path, "r").read()
	pos = old.find("/*\n * GENERATED")
	if pos == -1:
		raise Exception("Can't find marker in %s" % path)
	new = old[:pos]
	new += "/*\n * GENERATED BY disOps at %s\n */\n\n" % time.asctime()
	new += lists
	open(path, "w").write(new)
	print("Succeeded")

def main():
	# Init the 80x86/x64 instructions sets DB.
	db = x86db.InstructionsDB()
	x86InstructionsSet = x86sets.Instructions(db.SetInstruction)
	# Generate all tables of id's and pointers with the instructions themselves.
	mnemonicsIds, lists = x86generator.CreateTables(db)
	# Rewrite C instructions tables.
	WriteInstsC(lists)
	# Rewrite mnemonics of the C source code.
	WriteMnemonicsC(mnemonicsIds)
	# Rewrite mnemonics for the Python module.
	WriteMnemonicsPython(mnemonicsIds)
	# Rewrite mnemonics for the Java binding example code.
	WriteMnemonicsJava(mnemonicsIds)
	# C#:
	# Note that it will update its mnemonics upon compilation by taking them directly from the C code.

main()
