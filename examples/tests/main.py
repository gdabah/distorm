#import distorm
from pyasm import *
from distorm3 import *

_REGS = Registers

def decode(x, mode = 1):
	sizes = [16, 32, 64]
	x = Assemble(x, sizes[mode])
	print x.encode('hex')
	#print distorm.Decode(0, x, mode)
	print Decode(0, x, mode)

#decode("bswap ecx", 1)
#distorm3.Decode(0, "480fc3c0".decode('hex'), 2)


def xxx(x):
	buf = "".join(map(lambda txt: Assemble(txt, 32), x.split("\n")))
	print ",0x".join(map(lambda x: "%02x" % ord(x), buf))
	return Decode(0, buf, Decode32Bits)[0]

def yyy(inst):
	print "%x (%d): " % (inst["addr"], inst["size"])
	print inst
	ops = filter(lambda x:x is not None, inst["ops"])
	for o in ops:
		if o["type"] == O_REG:
			print _REGS[o["index"]]
		elif o["type"] == O_IMM:
			print hex(inst["imm"])
		elif o["type"] == O_MEM:
			print "[",
			if inst["base"] != R_NONE:
				print _REGS[inst["base"]],
				print "+",
			print _REGS[o["index"]],
			if inst["scale"] != 0:
				print "*%d" % inst["scale"],
			if inst["dispSize"] != 0:
				print " + 0x%x" % (inst["disp"]),
			print "]"
		elif o["type"] == O_SMEM:
			print "[%s" % (_REGS[o["index"]]),
			if inst["dispSize"] != 0:
				print " + 0x%x" % (inst["disp"]),
			print "]"
		elif o["type"] == O_DISP:
			print "[0x%x]" % inst["disp"]
		elif o["type"] == O_PC:
			print hex(inst["imm"])

#yyy(Decode(0, "0fae38".decode('hex'), Decode32Bits)[0])
yyy(xxx("mov eax, [ebp*4]"))
