# All VIAL and diStorm3 code are based on the order of this list, do NOT edit!
REGISTERS = [
	"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "XX",
	"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D", "XX",
	"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W", "XX",
	"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B", "XX",
	"SPL", "BPL", "SIL", "DIL", "XX",
	"ES", "CS", "SS", "DS", "FS", "GS", "XX",
	"RIP", "XX",
	"ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7", "XX",
	"MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7", "XX",
	"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15", "XX",
	"YMM0", "YMM1", "YMM2", "YMM3", "YMM4", "YMM5", "YMM6", "YMM7", "YMM8", "YMM9", "YMM10", "YMM11", "YMM12", "YMM13", "YMM14", "YMM15", "XX",
	"CR0", "", "CR2", "CR3", "CR4", "", "", "", "CR8", "XX",
	"DR0", "DR1", "DR2", "DR3", "", "", "DR6", "DR7"]
	
regsText = "const _WRegister _REGISTERS[] = {\n\t"
regsEnum = "typedef enum {\n\t"
old = "*"
unused = 0
for i in REGISTERS:
	if old != "*":
		if old == "XX":
			regsText += "\n\t"
			regsEnum += "\n\t"
			old = i
			continue
		else:
			regsText += "{%d, \"%s\"}," % (len(old), old)
			if len(old):
				regsEnum += "R_%s," % old
			else:
				regsEnum += "R_UNUSED%d," % unused
				unused += 1
			if i != "XX":
				regsText += " "
				regsEnum += " "
	old = i
regsText += "{%d, \"%s\"},\n\t{0, \"\"} /* There must be an empty last reg, see strcat_WSR. */\n};\n" % (len(old), old)
regsEnum += "R_" + old + "\n} _RegisterType;\n"
	
print(regsEnum)
print(regsText)
	