#
# Gil Dabah 2006
# Tests for diStorm3
#

import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import ctypes

import distorm3
from distorm3._generated import Registers, Mnemonics

# We require YASM assembler to work.
# Set YASM_PATH envar to its full binary path.
YASM_PATH = os.environ.get("YASM_PATH", "yasm")

REG_NONE = 255

class _Registers(object):
	def __init__(self):
		for index, name in enumerate(distorm3.Registers):
			if name:
				setattr(_Registers, name, index)

Regs = _Registers()
fbin = []

def Assemble(text, mode):
	lines = text.replace("\n", "\r\n")
	lines = ("bits %d\r\n" % mode) + lines
	asm_name = ""
	with tempfile.NamedTemporaryFile(suffix=".asm", prefix="distorm3-test-", mode="wb+", delete=False) as asm_file:
		asm_file.write(lines.encode())
		asm_file.flush() # Doesn't work instantly on windows. :(
		asm_name = asm_file.name
		asm_file.close()
		out_name = asm_name + ".out"
		cmd = [YASM_PATH, "-m%s" % ("amd64" if mode == 64 else "x86"), asm_name, "-o%s" % out_name]
		subprocess.check_call(cmd, shell=(sys.platform == "win32"))
		with open(out_name, "rb") as out_file:
			s = out_file.read()
		os.unlink(out_name)
	if len(asm_name):
		os.unlink(asm_name)
	return s

class Test(unittest.TestCase):
	def __init__(self):
		unittest.TestCase.__init__(self, "test_dummy")
	def test_dummy(self):
		self.fail("dummy")

class InstBin(Test):
	def __init__(self, bin, mode, features, address):
		Test.__init__(self)
		try:
			bin = bin.decode("hex")
		except:
			bin = bytes.fromhex(bin)
		#fbin[mode].write(bin)
		self.insts = distorm3.Decompose(address, bin, mode, features)
		self.inst = self.insts[0]
	def check_valid(self, instsNo = 1):
		self.assertNotEqual(self.inst.rawFlags, 65535)
		self.assertEqual(len(self.insts), instsNo)
	def check_invalid(self):
		self.assertEqual(self.inst.rawFlags, 65535)
	def check_mnemonic(self, mnemonic, instNo = 0):
		self.assertNotEqual(self.inst.rawFlags, 65535)
		self.assertEqual(self.insts[instNo].mnemonic, mnemonic)

class Inst(Test):
	def __init__(self, instText, mode, instNo, features):
		Test.__init__(self)
		modeSize = [16, 32, 64][mode]
		bin = Assemble(instText, modeSize)
		#print map(lambda x: hex(ord(x)), bin)
		#fbin[mode].write(bin)
		self.insts = distorm3.Decompose(0, bin, mode, features)
		self.inst = self.insts[instNo]

	def check_mnemonic(self, mnemonic):
		self.assertEqual(self.inst.mnemonic, mnemonic)

	def check_imm(self, n, val, sz):
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_IMMEDIATE)
		self.assertEqual(self.inst.operands[n].size, sz)
		self.assertEqual(self.inst.operands[n].value, val)

	def check_reg(self, n, idx, sz):
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_REGISTER)
		self.assertEqual(self.inst.operands[n].index, idx)
		self.assertEqual(self.inst.operands[n].size, sz)

	def check_pc(self, val, sz):
		self.assertEqual(self.inst.operands[0].type, distorm3.OPERAND_IMMEDIATE)
		self.assertEqual(self.inst.operands[0].size, sz)
		self.assertEqual(self.inst.operands[0].value, val)

	def check_disp(self, n, val, dispSize, derefSize):
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_MEMORY)
		self.assertEqual(self.inst.operands[n].dispSize, dispSize)
		self.assertEqual(self.inst.operands[n].size, derefSize)
		self.assertEqual(self.inst.operands[n].disp, val)

	def check_abs_disp(self, n, val, dispSize, derefSize):
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_ABSOLUTE_ADDRESS)
		self.assertEqual(self.inst.operands[n].dispSize, dispSize)
		self.assertEqual(self.inst.operands[n].size, derefSize)
		self.assertEqual(self.inst.operands[n].disp, val)

	def check_simple_deref(self, n, idx, derefSize):
		""" Checks whether a (simple) memory dereference type is used, size of deref is in ops.size.
		Displacement is ignored in this check. """
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_MEMORY)
		self.assertEqual(self.inst.operands[n].size, derefSize)
		self.assertEqual(self.inst.operands[n].index, idx)

	def check_deref(self, n, idx, base, derefSize):
		""" Checks whether a memory dereference type is used, size of deref is in ops.size.
			Base registers is in inst.base.
			Displacement is ignored in this check. """
		self.assertEqual(self.inst.operands[n].type, distorm3.OPERAND_MEMORY)
		self.assertEqual(self.inst.operands[n].size, derefSize)
		self.assertEqual(self.inst.operands[n].index, idx)
		self.assertEqual(self.inst.operands[n].base, base)

	def check_type_size(self, n, t, sz):
		self.assertEqual(self.inst.operands[n].type, t)
		self.assertEqual(self.inst.operands[n].size, sz)

	def check_addr_size(self, sz):
		self.assertEqual({0: 16, 1: 32, 2: 64}[(self.inst.rawFlags >> 10) & 3], sz)

def I16(instText, instNo = 0, features = 0):
	return Inst(instText, distorm3.Decode16Bits, instNo, features)

def IB16(bin, features = 0, address = 0):
	return InstBin(bin, distorm3.Decode16Bits, features, address)

def I32(instText, features = 0):
	return Inst(instText, distorm3.Decode32Bits, 0, features)

def IB32(bin, features = 0, address = 0):
	return InstBin(bin, distorm3.Decode32Bits, features, address)

def I64(instText, features = 0):
	return Inst(instText, distorm3.Decode64Bits, 0, features)

def IB64(bin, features = 0, address = 0):
	return InstBin(bin, distorm3.Decode64Bits, features, address)

def ABS64(x):
	return x
	#return struct.unpack("q", struct.pack("Q", x))[0]

class TestMode16(unittest.TestCase):
	Derefs = ["BX + SI", "BX + DI", "BP + SI", "BP + DI", "SI", "DI", "BP", "BX"]
	DerefsInfo = [(Regs.BX, Regs.SI), (Regs.BX, Regs.DI), (Regs.BP, Regs.SI), (Regs.BP, Regs.DI),
				  (Regs.SI,), (Regs.DI,), (Regs.BP,), (Regs.BX,)]
	def test_none(self):
		self.assertFalse(len(I16("cbw").inst.operands) > 0)
	def test_imm8(self):
		I16("int 0x55").check_imm(0, 0x55, 8)
	def test_imm16(self):
		I16("ret 0x1122").check_imm(0, 0x1122, 16)
	def test_seimm32(self):
		I16("mov ax, 0xff80").check_imm(1, 0xff80, 16)
		self.assertTrue(str(IB16("BA8080").inst).find("0x8080") != -1)
	def test_imm_full(self):
		I16("push 0x1234").check_imm(0, 0x1234, 16)
	def test_imm_aadm(self):
		I16("aam").check_imm(0, 0xa, 8)
		I16("aam 0x15").check_imm(0, 0x15, 8)
		I16("aad").check_imm(0, 0xa, 8)
		I16("aad 0x51").check_imm(0, 0x51, 8)
	def test_seimm(self):
		I16("push 5").check_imm(0, 0x5, 8)
		a = I16("push -6")
		self.assertTrue(str(a.inst).find("-0x6") != -1)
		self.assertEqual(a.inst.size, 2)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 8)
		self.assertFalse(ABS64(a.inst.operands[0].value) != -6)
		a = I16("db 0x66\n push -5")
		self.assertEqual(a.inst.size, 3)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 32)
		self.assertFalse(ABS64(a.inst.operands[0].value) != -5)
	def test_imm16_1_imm8_2(self):
		a = I16("enter 0x1234, 0x40")
		a.check_imm(0, 0x1234, 16)
		a.check_imm(1, 0x40, 8)
	def test_imm8_1_imm8_2(self):
		a = I16("extrq xmm0, 0x55, 0xff")
		a.check_imm(1, 0x55, 8)
		a.check_imm(2, 0xff, 8)
	def test_reg8(self):
		I16("inc dh").check_reg(0, Regs.DH, 8)
	def test_reg16(self):
		I16("arpl ax, bp").check_reg(1, Regs.BP, 16)
	def test_reg_full(self):
		I16("dec di").check_reg(0, Regs.DI, 16)
	def test_reg32(self):
		I16("movmskps ebx, xmm6").check_reg(0, Regs.EBX, 32)
	def test_reg32_64(self):
		I16("cvttsd2si esp, xmm3").check_reg(0, Regs.ESP, 32)
	def test_freg32_64_rm(self):
		I16("mov cr0, eax").check_reg(1, Regs.EAX, 32)
	def test_rm8(self):
		I16("seto dh").check_reg(0, Regs.DH, 8)
	def test_rm16(self):
		I16("str di").check_reg(0, Regs.DI, 16)
	def test_rm_full(self):
		I16("push bp").check_reg(0, Regs.BP, 16)
	def test_rm32_64(self):
		I16("movd xmm0, ebx").check_reg(1, Regs.EBX, 32)
	def test_fpum16(self):
		I16("fiadd word [bx]").check_simple_deref(0, Regs.BX, 16)
	def test_fpum32(self):
		I16("fisttp dword [si]").check_simple_deref(0, Regs.SI, 32)
	def test_fpum64(self):
		I16("fadd qword [esp]").check_simple_deref(0, Regs.ESP, 64)
	def test_fpum80(self):
		I16("fbld [eax]").check_simple_deref(0, Regs.EAX, 80)
	def test_r32_m8(self):
		I16("pinsrb xmm4, eax, 0x55").check_reg(1, Regs.EAX, 32)
		I16("pinsrb xmm4, [bx], 0x55").check_simple_deref(1, Regs.BX, 8)
	def test_r32_m16(self):
		I16("pinsrw xmm4, edi, 0x55").check_reg(1, Regs.EDI, 32)
		I16("pinsrw xmm1, word [si], 0x55").check_simple_deref(1, Regs.SI, 16)
	def test_r32_64_m8(self):
		I16("pextrb eax, xmm4, 0xaa").check_reg(0, Regs.EAX, 32)
		I16("pextrb [bx], xmm2, 0xaa").check_simple_deref(0, Regs.BX, 8)
	def test_r32_64_m16(self):
		I16("pextrw esp, xmm7, 0x11").check_reg(0, Regs.ESP, 32)
		I16("pextrw [bp], xmm0, 0xbb").check_simple_deref(0, Regs.BP, 16)
	def test_rfull_m16(self):
		I16("smsw ax").check_reg(0, Regs.AX, 16)
		I16("smsw [bx]").check_simple_deref(0, Regs.BX, 16)
	def test_creg(self):
		I16("mov esp, cr3").check_reg(1, Regs.CR3, 32)
		#I16("mov esp, cr8").check_reg(1, Regs.CR8, 32)
	def test_dreg(self):
		I16("mov edi, dr7").check_reg(1, Regs.DR7, 32)
	def test_sreg(self):
		I16("mov ax, ds").check_reg(1, Regs.DS, 16)
		I16("mov ax, cs").check_reg(1, Regs.CS, 16)
	def test_seg(self):
		I16("push fs").check_reg(0, Regs.FS, 16)
		I16("db 0x66\n push es").check_reg(0, Regs.ES, 16)
	def test_acc8(self):
		I16("in al, 0x60").check_reg(0, Regs.AL, 8)
	def test_acc_full(self):
		I16("add ax, 0x100").check_reg(0, Regs.AX, 16)
	def test_acc_full_not64(self):
		I16("out 0x64, ax").check_reg(1, Regs.AX, 16)
	def test_mem16_full(self):
		I16("call far [bp]").check_simple_deref(0, Regs.BP, 16)
	def test_ptr16_full(self):
		a = I16("jmp 0xffff:0x1234").inst
		self.assertEqual(a.size, 5)
		self.assertEqual(a.operands[0].type, distorm3.OPERAND_FAR_MEMORY)
		self.assertEqual(a.operands[0].size, 16)
		self.assertEqual(a.operands[0].seg, 0xffff)
		self.assertEqual(a.operands[0].off, 0x1234)
	def test_mem16_3264(self):
		I16("sgdt [bx]").check_simple_deref(0, Regs.BX, 32)
	def test_relcb(self):
		a = I16("db 0xe9\ndw 0x00")
		a.check_pc(3, 16)
		a = I16("db 0xe2\ndb 0x50")
		a.check_pc(0x52, 8)
		a = I16("db 0xe2\ndb 0xfd")
		a.check_pc(-1, 8)
		a = I16("db 0x67\ndb 0xe2\ndb 0xf0")
		a.check_pc(-0xd, 8)
	def test_relc_full(self):
		a = I16("jmp 0x100")
		self.assertEqual(a.inst.size, 3)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 16)
	def test_mem(self):
		I16("lea ax, [bx]").check_simple_deref(1, Regs.BX, 0)
	def test_mem32(self):
		I16("movntss [ebx], xmm5").check_simple_deref(0, Regs.EBX, 32)
	def test_mem32_64(self):
		I16("movnti [ebx], eax").check_simple_deref(0, Regs.EBX, 32)
	def test_mem64(self):
		I16("movlps [edi], xmm7").check_simple_deref(0, Regs.EDI, 64)
	def test_mem128(self):
		I16("movntps [eax], xmm3").check_simple_deref(0, Regs.EAX, 128)
	def test_mem64_128(self):
		I16("cmpxchg8b [edx]").check_simple_deref(0, Regs.EDX, 64)
	def test_moffs8(self):
		I16("mov al, [0x1234]").check_abs_disp(1, 0x1234, 16, 8)
		I16("mov [dword 0x11112222], al").check_abs_disp(0, 0x11112222, 32, 8)
	def test_moff_full(self):
		I16("mov [0x8765], ax").check_abs_disp(0, 0x8765, 16, 16)
		I16("mov ax, [dword 0x11112222]").check_abs_disp(1, 0x11112222, 32, 16)
	def test_const1(self):
		I16("shl si, 1").check_imm(1, 1, 8)
	def test_regcl(self):
		I16("rcl bp, cl").check_reg(1, Regs.CL, 8)
	def test_ib_rb(self):
		I16("mov dl, 0x88").check_reg(0, Regs.DL, 8)
	def test_ib_r_dw_qw(self):
		I16("bswap ecx").check_reg(0, Regs.ECX, 32)
	def test_ib_r_full(self):
		I16("inc si").check_reg(0, Regs.SI, 16)
	def test_regi_esi(self):
		I16("lodsb").check_simple_deref(1, Regs.SI, 8)
		I16("cmpsw").check_simple_deref(0, Regs.SI, 16)
		I16("lodsd").check_simple_deref(1, Regs.SI, 32)
	def test_regi_edi(self):
		I16("movsb").check_simple_deref(0, Regs.DI, 8)
		I16("scasw").check_simple_deref(0, Regs.DI, 16)
		I16("stosd").check_simple_deref(0, Regs.DI, 32)
	def test_regi_ebxal(self):
		a = I16("xlatb")
		a.check_type_size(0, distorm3.OPERAND_MEMORY, 8)
		self.assertFalse(a.inst.operands[0].index != Regs.AL)
		self.assertFalse(a.inst.operands[0].base != Regs.BX)
	def test_regi_eax(self):
		I16("vmrun [ax]").check_simple_deref(0, Regs.AX, 16)
	def test_regdx(self):
		I16("in ax, dx").check_reg(1, Regs.DX, 16)
	def test_regecx(self):
		I16("invlpga [eax], ecx").check_reg(1, Regs.ECX, 32)
	def test_fpu_si(self):
		I16("fxch st4").check_reg(0, Regs.ST4, 32)
	def test_fpu_ssi(self):
		a = I16("fcmovnbe st0, st3")
		a.check_reg(0, Regs.ST0, 32)
		a.check_reg(1, Regs.ST3, 32)
	def test_fpu_sis(self):
		a = I16("fadd st3, st0")
		a.check_reg(0, Regs.ST3, 32)
		a.check_reg(1, Regs.ST0, 32)
	def test_mm(self):
		I16("pand mm0, mm7").check_reg(0, Regs.MM0, 64)
	def test_mm_rm(self):
		I16("psllw mm0, 0x55").check_reg(0, Regs.MM0, 64)
	def test_mm32(self):
		I16("punpcklbw mm1, [si]").check_simple_deref(1, Regs.SI, 32)
	def test_mm64(self):
		I16("packsswb mm3, [bx]").check_simple_deref(1, Regs.BX, 64)
	def test_xmm(self):
		I16("orps xmm5, xmm4").check_reg(0, Regs.XMM5, 128)
	def test_xmm_rm(self):
		I16("psrlw xmm6, 0x12").check_reg(0, Regs.XMM6, 128)
	def test_xmm16(self):
		I16("pmovsxbq xmm3, [bp]").check_simple_deref(1, Regs.BP, 16)
	def test_xmm32(self):
		I16("pmovsxwq xmm5, [di]").check_simple_deref(1, Regs.DI, 32)
	def test_xmm64(self):
		I16("roundsd xmm6, [si], 0x55").check_simple_deref(1, Regs.SI, 64)
	def test_xmm128(self):
		I16("roundpd xmm7, [bx], 0xaa").check_simple_deref(1, Regs.BX, 128)
	def test_regxmm0(self):
		I16("blendvpd xmm1, xmm3, xmm0").check_reg(2, Regs.XMM0, 128)
	def test_disp_only(self):
		a = I16("add [0x1234], bx")
		a.check_type_size(0, distorm3.OPERAND_ABSOLUTE_ADDRESS, 16)
		self.assertFalse(a.inst.operands[0].dispSize != 16)
		self.assertFalse(a.inst.operands[0].disp != 0x1234)
	def test_modrm(self):
		texts = ["ADD [%s], AX" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I16(i[1])
			if len(self.DerefsInfo[i[0]]) == 2:
				a.check_deref(0, self.DerefsInfo[i[0]][1], self.DerefsInfo[i[0]][0], 16)
			else:
				a.check_simple_deref(0, self.DerefsInfo[i[0]][0], 16)
	def test_modrm_disp8(self):
		texts = ["ADD [%s + 0x55], AX" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I16(i[1])
			if len(self.DerefsInfo[i[0]]) == 2:
				a.check_deref(0, self.DerefsInfo[i[0]][1], self.DerefsInfo[i[0]][0], 16)
			else:
				a.check_simple_deref(0, self.DerefsInfo[i[0]][0], 16)
			self.assertFalse(a.inst.operands[0].dispSize != 8)
			self.assertFalse(a.inst.operands[0].disp != 0x55)
	def test_modrm_disp16(self):
		texts = ["ADD [%s + 0x3322], AX" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I16(i[1])
			if len(self.DerefsInfo[i[0]]) == 2:
				a.check_deref(0, self.DerefsInfo[i[0]][1], self.DerefsInfo[i[0]][0], 16)
			else:
				a.check_simple_deref(0, self.DerefsInfo[i[0]][0], 16)
			self.assertFalse(a.inst.operands[0].dispSize != 16)
			self.assertFalse(a.inst.operands[0].disp != 0x3322)

class TestMode32(unittest.TestCase):
	Derefs = ["EAX", "ECX", "EDX", "EBX", "EBP", "ESI", "EDI"]
	DerefsInfo = [Regs.EAX, Regs.ECX, Regs.EDX, Regs.EBX, Regs.EBP, Regs.ESI, Regs.EDI]
	def test_none(self):
		self.assertFalse(len(I32("cdq").inst.operands) > 0)
	def test_imm8(self):
		I32("int 0x55").check_imm(0, 0x55, 8)
	def test_imm16(self):
		I32("ret 0x1122").check_imm(0, 0x1122, 16)
	def test_seimm32(self):
		I32("mov eax, 0xff112233").check_imm(1, 0xff112233, 32)
		self.assertTrue(str(IB32("BA5F6038CE").inst).find("0xce38605f") != -1)
	def test_imm_full(self):
		I32("push 0x12345678").check_imm(0, 0x12345678, 32)
	def test_imm_aadm(self):
		I32("aam").check_imm(0, 0xa, 8)
		I32("aam 0x15").check_imm(0, 0x15, 8)
		I32("aad").check_imm(0, 0xa, 8)
		I32("aad 0x51").check_imm(0, 0x51, 8)
	def test_seimm(self):
		I32("push 6").check_imm(0, 0x6, 8)
		a = I32("push -7")
		self.assertEqual(a.inst.size, 2)
		self.assertTrue(str(a.inst).find("-0x7") != -1)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 8)
		self.assertFalse(ABS64(a.inst.operands[0].value) != -7)
		a = I32("db 0x66\n push -5")
		self.assertEqual(a.inst.size, 3)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 16)
		self.assertFalse(ABS64(a.inst.operands[0].value) != -5)
	def test_imm16_1_imm8_2(self):
		a = I32("enter 0x1234, 0x40")
		a.check_imm(0, 0x1234, 16)
		a.check_imm(1, 0x40, 8)
	def test_imm8_1_imm8_2(self):
		a = I32("extrq xmm0, 0x55, 0xff")
		a.check_imm(1, 0x55, 8)
		a.check_imm(2, 0xff, 8)
	def test_reg8(self):
		I32("inc dh").check_reg(0, Regs.DH, 8)
	def test_reg16(self):
		I32("arpl ax, bp").check_reg(1, Regs.BP, 16)
	def test_reg_full(self):
		I32("dec edi").check_reg(0, Regs.EDI, 32)
	def test_reg32(self):
		I32("movmskps ebx, xmm6").check_reg(0, Regs.EBX, 32)
	def test_reg32_64(self):
		I32("cvttsd2si esp, xmm3").check_reg(0, Regs.ESP, 32)
	def test_freg32_64_rm(self):
		I32("mov cr0, eax").check_reg(1, Regs.EAX, 32)
	def test_rm8(self):
		I32("seto dh").check_reg(0, Regs.DH, 8)
	def test_rm16(self):
		I32("verr di").check_reg(0, Regs.DI, 16)
	def test_rm_full(self):
		I32("push ebp").check_reg(0, Regs.EBP, 32)
	def test_rm32_64(self):
		I32("movd xmm0, ebx").check_reg(1, Regs.EBX, 32)
	def test_fpum16(self):
		I32("fiadd word [ebx]").check_simple_deref(0, Regs.EBX, 16)
	def test_fpum32(self):
		I32("fisttp dword [esi]").check_simple_deref(0, Regs.ESI, 32)
	def test_fpum64(self):
		I32("fadd qword [esp]").check_simple_deref(0, Regs.ESP, 64)
	def test_fpum80(self):
		I32("fbld [eax]").check_simple_deref(0, Regs.EAX, 80)
	def test_r32_m8(self):
		I32("pinsrb xmm4, eax, 0x55").check_reg(1, Regs.EAX, 32)
		I32("pinsrb xmm4, [ebx], 0x55").check_simple_deref(1, Regs.EBX, 8)
	def test_r32_m16(self):
		I32("pinsrw xmm4, edi, 0x55").check_reg(1, Regs.EDI, 32)
		I32("pinsrw xmm1, word [esi], 0x55").check_simple_deref(1, Regs.ESI, 16)
	def test_r32_64_m8(self):
		I32("pextrb eax, xmm4, 0xaa").check_reg(0, Regs.EAX, 32)
		I32("pextrb [ebx], xmm2, 0xaa").check_simple_deref(0, Regs.EBX, 8)
	def test_r32_64_m16(self):
		I32("pextrw esp, xmm7, 0x11").check_reg(0, Regs.ESP, 32)
		I32("pextrw [ebp], xmm0, 0xbb").check_simple_deref(0, Regs.EBP, 16)
	def test_rfull_m16(self):
		I32("smsw eax").check_reg(0, Regs.EAX, 32)
		I32("smsw [ebx]").check_simple_deref(0, Regs.EBX, 16)
	def test_creg(self):
		I32("mov esp, cr3").check_reg(1, Regs.CR3, 32)
	def test_dreg(self):
		I32("mov edi, dr7").check_reg(1, Regs.DR7, 32)
	def test_sreg(self):
		I32("mov ax, ds").check_reg(1, Regs.DS, 16)
		I32("mov ax, cs").check_reg(1, Regs.CS, 16)
	def test_seg(self):
		I32("push ss").check_reg(0, Regs.SS, 16)
		I32("db 0x66\n push ds").check_reg(0, Regs.DS, 16)
	def test_acc8(self):
		I32("in al, 0x60").check_reg(0, Regs.AL, 8)
	def test_acc_full(self):
		I32("add eax, 0x100").check_reg(0, Regs.EAX, 32)
	def test_acc_full_not64(self):
		I32("out 0x64, eax").check_reg(1, Regs.EAX, 32)
	def test_mem16_full(self):
		I32("call far [ebp]").check_simple_deref(0, Regs.EBP, 32)
	def test_ptr16_full(self):
		a = I32("jmp 0xffff:0x12345678").inst
		self.assertEqual(a.size, 7)
		self.assertEqual(a.operands[0].type, distorm3.OPERAND_FAR_MEMORY)
		self.assertEqual(a.operands[0].size, 32)
		self.assertEqual(a.operands[0].seg, 0xffff)
		self.assertEqual(a.operands[0].off, 0x12345678)
	def test_mem16_3264(self):
		I32("sgdt [ebx]").check_simple_deref(0, Regs.EBX, 32)
	def test_relcb(self):
		a = I32("db 0xe9\ndd 0x00")
		a.check_pc(5, 32)
		a = I32("db 0xe2\ndb 0x50")
		a.check_pc(0x52, 8)
		a = I32("db 0xe2\ndb 0xfd")
		a.check_pc(-1, 8)
		a = I32("db 0x67\ndb 0xe2\ndb 0xf0")
		a.check_pc(-0xd, 8)
	def test_relc_full(self):
		a = I32("jmp 0x100")
		self.assertEqual(a.inst.size, 5)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 32)
	def test_mem(self):
		I32("lea ax, [ebx]").check_simple_deref(1, Regs.EBX, 0)
	def test_mem32(self):
		I32("movntss [ebx], xmm5").check_simple_deref(0, Regs.EBX, 32)
	def test_mem32_64(self):
		I32("movnti [edi], eax").check_simple_deref(0, Regs.EDI, 32)
	def test_mem64(self):
		I32("movlps [edi], xmm7").check_simple_deref(0, Regs.EDI, 64)
	def test_mem128(self):
		I32("movntps [eax], xmm3").check_simple_deref(0, Regs.EAX, 128)
	def test_mem64_128(self):
		I32("cmpxchg8b [edx]").check_simple_deref(0, Regs.EDX, 64)
	def test_moffs8(self):
		I32("mov al, [word 0x5678]").check_abs_disp(1, 0x5678, 16, 8)
		I32("mov [0x11112222], al").check_abs_disp(0, 0x11112222, 32, 8)
	def test_moff_full(self):
		I32("mov [word 0x4321], eax").check_abs_disp(0, 0x4321, 16, 32)
		I32("mov eax, [0x11112222]").check_abs_disp(1, 0x11112222, 32, 32)
	def test_const1(self):
		I32("shl esi, 1").check_imm(1, 1, 8)
	def test_regcl(self):
		I32("rcl ebp, cl").check_reg(1, Regs.CL, 8)
	def test_ib_rb(self):
		I32("mov dl, 0x88").check_reg(0, Regs.DL, 8)
	def test_ib_r_dw_qw(self):
		I32("bswap ecx").check_reg(0, Regs.ECX, 32)
	def test_ib_r_full(self):
		I32("inc esi").check_reg(0, Regs.ESI, 32)
	def test_regi_esi(self):
		I32("lodsb").check_simple_deref(1, Regs.ESI, 8)
		I32("cmpsw").check_simple_deref(0, Regs.ESI, 16)
		I32("lodsd").check_simple_deref(1, Regs.ESI, 32)
	def test_regi_edi(self):
		I32("movsb").check_simple_deref(0, Regs.EDI, 8)
		I32("scasw").check_simple_deref(0, Regs.EDI, 16)
		I32("stosd").check_simple_deref(0, Regs.EDI, 32)
	def test_regi_ebxal(self):
		a = I32("xlatb")
		a.check_type_size(0, distorm3.OPERAND_MEMORY, 8)
		self.assertFalse(a.inst.operands[0].index != Regs.AL)
		self.assertFalse(a.inst.operands[0].base != Regs.EBX)
	def test_regi_eax(self):
		I32("vmrun [eax]").check_simple_deref(0, Regs.EAX, 32)
	def test_regdx(self):
		I32("in eax, dx").check_reg(1, Regs.DX, 16)
	def test_regecx(self):
		I32("invlpga [eax], ecx").check_reg(1, Regs.ECX, 32)
	def test_fpu_si(self):
		I32("fxch st4").check_reg(0, Regs.ST4, 32)
	def test_fpu_ssi(self):
		a = I32("fcmovnbe st0, st3")
		a.check_reg(0, Regs.ST0, 32)
		a.check_reg(1, Regs.ST3, 32)
	def test_fpu_sis(self):
		a = I32("fadd st3, st0")
		a.check_reg(0, Regs.ST3, 32)
		a.check_reg(1, Regs.ST0, 32)
	def test_mm(self):
		I32("pand mm0, mm7").check_reg(0, Regs.MM0, 64)
	def test_mm_rm(self):
		I32("psllw mm0, 0x55").check_reg(0, Regs.MM0, 64)
	def test_mm32(self):
		I32("punpcklbw mm1, [esi]").check_simple_deref(1, Regs.ESI, 32)
	def test_mm64(self):
		I32("packsswb mm3, [ebx]").check_simple_deref(1, Regs.EBX, 64)
	def test_xmm(self):
		I32("orps xmm5, xmm4").check_reg(0, Regs.XMM5, 128)
	def test_xmm_rm(self):
		I32("psrlw xmm6, 0x12").check_reg(0, Regs.XMM6, 128)
	def test_xmm16(self):
		I32("pmovsxbq xmm3, [ebp]").check_simple_deref(1, Regs.EBP, 16)
	def test_xmm32(self):
		I32("pmovsxwq xmm5, [edi]").check_simple_deref(1, Regs.EDI, 32)
	def test_xmm64(self):
		I32("roundsd xmm6, [esi], 0x55").check_simple_deref(1, Regs.ESI, 64)
	def test_xmm128(self):
		I32("roundpd xmm7, [ebx], 0xaa").check_simple_deref(1, Regs.EBX, 128)
	def test_regxmm0(self):
		I32("blendvpd xmm1, xmm3, xmm0").check_reg(2, Regs.XMM0, 128)
	def test_cr8(self):
		I32("db 0xf0\n mov cr0, eax").check_reg(0, Regs.CR8, 32)
	def test_disp_only(self):
		a = I32("add [0x12345678], ebx")
		a.check_type_size(0, distorm3.OPERAND_ABSOLUTE_ADDRESS, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 32)
		self.assertFalse(a.inst.operands[0].disp != 0x12345678)
	def test_modrm(self):
		texts = ["ADD [%s], EDI" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I32(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 32)
	def test_modrm_disp8(self):
		texts = ["ADD [%s + 0x55], ESI" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I32(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 32)
			self.assertFalse(a.inst.operands[0].dispSize != 8)
			self.assertFalse(a.inst.operands[0].disp != 0x55)
	def test_modrm_disp32(self):
		texts = ["ADD [%s + 0x33221144], EDX" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I32(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 32)
			self.assertFalse(a.inst.operands[0].dispSize != 32)
			self.assertFalse(a.inst.operands[0].disp != 0x33221144)
	def test_base_ebp(self):
		a = I32("mov [ebp+0x55], eax")
		a.check_simple_deref(0, Regs.EBP, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 8)
		self.assertFalse(a.inst.operands[0].disp != 0x55)
		a = I32("mov [ebp+0x55+eax], eax")
		a.check_deref(0, Regs.EAX, Regs.EBP, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 8)
		self.assertFalse(a.inst.operands[0].disp != 0x55)
		a = I32("mov [ebp+0x55443322], eax")
		a.check_simple_deref(0, Regs.EBP, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 32)
		self.assertFalse(a.inst.operands[0].disp != 0x55443322)
	Bases = ["EAX", "ECX", "EDX", "EBX", "ESP", "ESI", "EDI"]
	BasesInfo = [Regs.EAX, Regs.ECX, Regs.EDX, Regs.EBX, Regs.ESP, Regs.ESI, Regs.EDI]
	Indices = ["EAX", "ECX", "EDX", "EBX", "EBP", "ESI", "EDI"]
	IndicesInfo = [Regs.EAX, Regs.ECX, Regs.EDX, Regs.EBX, Regs.EBP, Regs.ESI, Regs.EDI]
	def test_bases(self):
		for i in enumerate(self.Bases):
			a = I32("cmp ebp, [%s]" % (i[1]))
			a.check_simple_deref(1, self.BasesInfo[i[0]], 32)
	def test_bases_disp32(self):
		for i in enumerate(self.Bases):
			a = I32("cmp ebp, [%s+0x12345678]" % (i[1]))
			a.check_simple_deref(1, self.BasesInfo[i[0]], 32)
			self.assertFalse(a.inst.operands[1].dispSize != 32)
			self.assertFalse(a.inst.operands[1].disp != 0x12345678)
	def test_scales(self):
		for i in enumerate(self.Indices):
			# A scale of 2 causes the scale to be omitted and changed from reg*2 to reg+reg.
			for s in [4, 8]:
				a = I32("and bp, [%s*%d]" % (i[1], s))
				a.check_deref(1, self.IndicesInfo[i[0]], None, 16)
				self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I32("or bp, [%s*%d + %s]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 16)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib_disp8(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I32("xor al, [%s*%d + %s + 0x55]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 8)
					self.assertFalse(a.inst.operands[1].dispSize != 8)
					self.assertFalse(a.inst.operands[1].disp != 0x55)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib_disp32(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I32("sub ebp, [%s*%d + %s + 0x55aabbcc]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 32)
					self.assertFalse(a.inst.operands[1].dispSize != 32)
					self.assertFalse(a.inst.operands[1].disp != 0x55aabbcc)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)

class TestMode64(unittest.TestCase):
	Derefs = ["RAX", "RCX", "RDX", "RBX", "RBP", "RSI", "RDI"]
	DerefsInfo = [Regs.RAX, Regs.RCX, Regs.RDX, Regs.RBX, Regs.RBP, Regs.RSI, Regs.RDI]
	def test_none(self):
		self.assertFalse(len(I64("cdq").inst.operands) > 0)
	def test_imm8(self):
		I64("int 0x55").check_imm(0, 0x55, 8)
	def test_imm16(self):
		I64("ret 0x1122").check_imm(0, 0x1122, 16)
	def test_seimm32(self):
		I64("mov eax, 0xff112233").check_imm(1, -15654349, 32)
		self.assertTrue(str(IB64("BA5F6038CE").inst).find("0xce38605f") != -1)
	def test_imm_full(self):
		I64("push 0x12345678").check_imm(0, 0x12345678, 32)
		I64("mov rax, 0x1234567812345678").check_imm(1, 0x1234567812345678, 64)
	def test_imm_aadm(self):
		#I64("aam").check_imm(0, 0xa, 8)
		#I64("aam 0x15").check_imm(0, 0x15, 8)
		#I64("aad").check_imm(0, 0xa, 8)
		#I64("aad 0x51").check_imm(0, 0x51, 8)
		pass
	def test_seimm(self):
		I64("push 6").check_imm(0, 0x6, 8)
		a = I64("push -7")
		self.assertEqual(a.inst.size, 2)
		self.assertTrue(str(a.inst).find("-0x7") != -1)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 8)
		self.assertFalse(ABS64(a.inst.operands[0].value) != -7)
	def test_imm16_1_imm8_2(self):
		a = I64("enter 0x1234, 0x40")
		a.check_imm(0, 0x1234, 16)
		a.check_imm(1, 0x40, 8)
	def test_imm8_1_imm8_2(self):
		a = I64("extrq xmm0, 0x55, 0xff")
		a.check_imm(1, 0x55, 8)
		a.check_imm(2, 0xff, 8)
	def test_reg8(self):
		I64("inc dh").check_reg(0, Regs.DH, 8)
	def test_reg_full(self):
		I64("dec rdi").check_reg(0, Regs.RDI, 64)
		I64("cmp r15, r14").check_reg(0, Regs.R15, 64)
		I64("cmp r8d, r9d").check_reg(0, Regs.R8D, 32)
		I64("cmp r9w, r8w").check_reg(0, Regs.R9W, 16)
	def test_reg32(self):
		I64("movmskps ebx, xmm6").check_reg(0, Regs.EBX, 32)
		I64("movmskps r11d, xmm6").check_reg(0, Regs.R11D, 32)
	def test_reg32_64(self):
		I64("cvttsd2si rsp, xmm3").check_reg(0, Regs.RSP, 64)
		I64("cvttsd2si r14, xmm3").check_reg(0, Regs.R14, 64)
	def test_freg32_64_rm(self):
		I64("mov cr0, rax").check_reg(1, Regs.RAX, 64)
		I64("mov cr0, r14").check_reg(1, Regs.R14, 64)
	def test_rm8(self):
		I64("seto dh").check_reg(0, Regs.DH, 8)
	def test_rm16(self):
		I64("verr di").check_reg(0, Regs.DI, 16)
		I64("verr r8w").check_reg(0, Regs.R8W, 16)
	def test_rm_full(self):
		I64("push rbp").check_reg(0, Regs.RBP, 64)
	def test_rm32_64(self):
		I64("movq xmm0, rdx").check_reg(1, Regs.RDX, 64)
		I64("movq xmm0, r10").check_reg(1, Regs.R10, 64)
		I64("cvtsi2sd xmm0, rdx").check_reg(1, Regs.RDX, 64)
		I64("vmread rax, rax").check_reg(1, Regs.RAX, 64)
	def test_rm16_32(self):
		I64("movsxd rax, eax").check_reg(1, Regs.EAX, 32)
		I64("movzx rax, ax").check_reg(1, Regs.AX, 16)
	def test_fpum16(self):
		I64("fiadd word [rbx]").check_simple_deref(0, Regs.RBX, 16)
	def test_fpum32(self):
		I64("fisttp dword [rsi]").check_simple_deref(0, Regs.RSI, 32)
	def test_fpum64(self):
		I64("fadd qword [rsp]").check_simple_deref(0, Regs.RSP, 64)
	def test_fpum80(self):
		I64("fbld [rax]").check_simple_deref(0, Regs.RAX, 80)
	def test_r32_m8(self):
		I64("pinsrb xmm4, eax, 0x55").check_reg(1, Regs.EAX, 32)
		I64("pinsrb xmm4, [rbx], 0x55").check_simple_deref(1, Regs.RBX, 8)
	def test_r32_m16(self):
		I64("pinsrw xmm4, edi, 0x55").check_reg(1, Regs.EDI, 32)
		I64("pinsrw xmm1, word [rsi], 0x55").check_simple_deref(1, Regs.RSI, 16)
		I64("pinsrw xmm1, r8d, 0x55").check_reg(1, Regs.R8D, 32)
	def test_r32_64_m8(self):
		I64("pextrb eax, xmm4, 0xaa").check_reg(0, Regs.EAX, 32)
		I64("pextrb [rbx], xmm2, 0xaa").check_simple_deref(0, Regs.RBX, 8)
	def test_r32_64_m16(self):
		I64("pextrw esp, xmm7, 0x11").check_reg(0, Regs.ESP, 32)
		I64("pextrw [rbp], xmm0, 0xbb").check_simple_deref(0, Regs.RBP, 16)
	def test_rfull_m16(self):
		I64("smsw eax").check_reg(0, Regs.EAX, 32)
		I64("smsw [rbx]").check_simple_deref(0, Regs.RBX, 16)
	def test_creg(self):
		I64("mov rsp, cr3").check_reg(1, Regs.CR3, 64)
		I64("mov cr8, rdx").check_reg(0, Regs.CR8, 64)
	def test_dreg(self):
		I64("mov rdi, dr7").check_reg(1, Regs.DR7, 64)
	def test_sreg(self):
		I64("mov ax, fs").check_reg(1, Regs.FS, 16)
		I64("mov ax, cs").check_reg(1, Regs.CS, 16)
	def test_seg(self):
		I64("push gs").check_reg(0, Regs.GS, 16)
	def test_acc8(self):
		I64("in al, 0x60").check_reg(0, Regs.AL, 8)
	def test_acc_full(self):
		I64("add rax, 0x100").check_reg(0, Regs.RAX, 64)
	def test_acc_full_not64(self):
		I64("out 0x64, eax").check_reg(1, Regs.EAX, 32)
		I64("db 0x48\nout 0x64, eax").check_reg(1, Regs.EAX, 32)
	def test_mem16_full(self):
		I64("call far [rbp]").check_simple_deref(0, Regs.RBP, 32)
		I64("db 0x48\n call far [rbp]").check_simple_deref(0, Regs.RBP, 64)
	def test_mem16_3264(self):
		I64("sgdt [rbx]").check_simple_deref(0, Regs.RBX, 64)
	def test_relcb(self):
		a = I64("db 0xe9\ndd 0x00")
		a.check_pc(5, 32)
		a = I64("db 0xe2\ndb 0x50")
		a.check_pc(0x52, 8)
		a = I64("db 0xe2\ndb 0xfd")
		a.check_pc(-1, 8)
		a = I64("db 0x67\ndb 0xe2\ndb 0xf0")
		a.check_pc(-0xd, 8)
	def test_relc_full(self):
		a = I64("jmp 0x100")
		self.assertEqual(a.inst.size, 5)
		a.check_type_size(0, distorm3.OPERAND_IMMEDIATE, 32)
	def test_mem(self):
		I64("lea ax, [rbx]").check_simple_deref(1, Regs.RBX, 0)
	def test_mem32(self):
		I64("movntss [rbx], xmm5").check_simple_deref(0, Regs.RBX, 32)
	def test_mem32_64(self):
		I64("movnti [rdi], eax").check_simple_deref(0, Regs.RDI, 32)
		I64("movnti [rbp], rax").check_simple_deref(0, Regs.RBP, 64)
	def test_mem64(self):
		I64("movlps [rdi], xmm7").check_simple_deref(0, Regs.RDI, 64)
	def test_mem128(self):
		I64("movntps [rax], xmm3").check_simple_deref(0, Regs.RAX, 128)
	def test_mem64_128(self):
		I64("cmpxchg8b [rdx]").check_simple_deref(0, Regs.RDX, 64)
		I64("cmpxchg16b [rbx]").check_simple_deref(0, Regs.RBX, 128)
	def test_moffs8(self):
		I64("mov al, [dword 0x12345678]").check_abs_disp(1, 0x12345678, 32, 8)
		I64("mov [qword 0xaaaabbbbccccdddd], al").check_abs_disp(0, 0xaaaabbbbccccdddd, 64, 8)
	def test_moff_full(self):
		I64("mov [dword 0xaaaabbbb], rax").check_abs_disp(0, 0xffffffffaaaabbbb, 32, 64)
		I64("mov rax, [qword 0xaaaabbbbccccdddd]").check_abs_disp(1, 0xaaaabbbbccccdddd, 64, 64)
	def test_const1(self):
		I64("shl rsi, 1").check_imm(1, 1, 8)
	def test_regcl(self):
		I64("rcl rbp, cl").check_reg(1, Regs.CL, 8)
	def test_ib_rb(self):
		I64("mov dl, 0x88").check_reg(0, Regs.DL, 8)
		I64("mov spl, 0x88").check_reg(0, Regs.SPL, 8)
		I64("mov r10b, 0x88").check_reg(0, Regs.R10B, 8)
	def test_ib_r_dw_qw(self):
		I64("bswap rcx").check_reg(0, Regs.RCX, 64)
		I64("bswap r10").check_reg(0, Regs.R10, 64)
		I64("push r10").check_reg(0, Regs.R10, 64)
	def test_ib_r_full(self):
		I64("inc rsi").check_reg(0, Regs.RSI, 64)
		I64("inc r9").check_reg(0, Regs.R9, 64)
		I64("push r10w").check_reg(0, Regs.R10W, 16)
		I64("xchg r10d, eax").check_reg(0, Regs.R10D, 32)
	def test_regi_esi(self):
		I64("lodsb").check_simple_deref(1, Regs.RSI, 8)
		I64("cmpsw").check_simple_deref(0, Regs.RSI, 16)
		I64("lodsd").check_simple_deref(1, Regs.RSI, 32)
		I64("lodsq").check_simple_deref(1, Regs.RSI, 64)
	def test_regi_edi(self):
		I64("movsb").check_simple_deref(0, Regs.RDI, 8)
		I64("scasw").check_simple_deref(0, Regs.RDI, 16)
		I64("stosd").check_simple_deref(0, Regs.RDI, 32)
		I64("stosq").check_simple_deref(0, Regs.RDI, 64)
	def test_regi_ebxal(self):
		a = I64("xlatb")
		a.check_type_size(0, distorm3.OPERAND_MEMORY, 8)
		self.assertFalse(a.inst.operands[0].index != Regs.AL)
		self.assertFalse(a.inst.operands[0].base != Regs.RBX)
	def test_regi_eax(self):
		I64("vmrun [rax]").check_simple_deref(0, Regs.RAX, 64)
	def test_regdx(self):
		#I64("in eax, dx").check_reg(1, Regs.DX, 16)
		pass
	def test_regecx(self):
		I64("invlpga [rax], ecx").check_reg(1, Regs.ECX, 32)
	def test_fpu_si(self):
		I64("fxch st4").check_reg(0, Regs.ST4, 32)
	def test_fpu_ssi(self):
		a = I64("fcmovnbe st0, st3")
		a.check_reg(0, Regs.ST0, 32)
		a.check_reg(1, Regs.ST3, 32)
	def test_fpu_sis(self):
		a = I64("fadd st3, st0")
		a.check_reg(0, Regs.ST3, 32)
		a.check_reg(1, Regs.ST0, 32)
	def test_mm(self):
		I64("pand mm0, mm7").check_reg(0, Regs.MM0, 64)
	def test_mm_rm(self):
		I64("psllw mm0, 0x55").check_reg(0, Regs.MM0, 64)
	def test_mm32(self):
		I64("punpcklbw mm1, [rsi]").check_simple_deref(1, Regs.RSI, 32)
	def test_mm64(self):
		I64("packsswb mm3, [rbx]").check_simple_deref(1, Regs.RBX, 64)
	def test_xmm(self):
		I64("orps xmm5, xmm4").check_reg(0, Regs.XMM5, 128)
		I64("orps xmm15, xmm4").check_reg(0, Regs.XMM15, 128)
	def test_xmm_rm(self):
		I64("psrlw xmm6, 0x12").check_reg(0, Regs.XMM6, 128)
		I64("psrlw xmm13, 0x12").check_reg(0, Regs.XMM13, 128)
	def test_xmm16(self):
		I64("pmovsxbq xmm3, [rbp]").check_simple_deref(1, Regs.RBP, 16)
	def test_xmm32(self):
		I64("pmovsxwq xmm5, [rdi]").check_simple_deref(1, Regs.RDI, 32)
	def test_xmm64(self):
		I64("roundsd xmm6, [rsi], 0x55").check_simple_deref(1, Regs.RSI, 64)
	def test_xmm128(self):
		I64("roundpd xmm7, [rbx], 0xaa").check_simple_deref(1, Regs.RBX, 128)
		I64("roundpd xmm7, xmm15, 0xaa").check_reg(1, Regs.XMM15, 128)
	def test_regxmm0(self):
		I64("blendvpd xmm1, xmm3, xmm0").check_reg(2, Regs.XMM0, 128)
	def test_disp_only(self):
		a = I64("add [0x12345678], rbx")
		a.check_type_size(0, distorm3.OPERAND_ABSOLUTE_ADDRESS, 64)
		self.assertFalse(a.inst.operands[0].dispSize != 32)
		self.assertFalse(a.inst.operands[0].disp != 0x12345678)
	def test_modrm(self):
		texts = ["ADD [%s], RDI" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I64(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 64)
	def test_modrm_disp8(self):
		texts = ["ADD [%s + 0x55], RSI" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I64(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 64)
			self.assertFalse(a.inst.operands[0].dispSize != 8)
			self.assertFalse(a.inst.operands[0].disp != 0x55)
	def test_modrm_disp32(self):
		texts = ["ADD [%s + 0x33221144], RDX" % i for i in self.Derefs]
		for i in enumerate(texts):
			a = I64(i[1])
			a.check_simple_deref(0, self.DerefsInfo[i[0]], 64)
			self.assertFalse(a.inst.operands[0].dispSize != 32)
			self.assertFalse(a.inst.operands[0].disp != 0x33221144)
	def test_base_rbp(self):
		a = I64("mov [rbp+0x55], eax")
		a.check_simple_deref(0, Regs.RBP, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 8)
		self.assertFalse(a.inst.operands[0].disp != 0x55)
		a = I64("mov [rbp+0x55443322], eax")
		a.check_simple_deref(0, Regs.RBP, 32)
		self.assertFalse(a.inst.operands[0].dispSize != 32)
		self.assertFalse(a.inst.operands[0].disp != 0x55443322)
	def test_base_rip(self):
		a = I64("mov [rip+0x12345678], rdx")
		a.check_simple_deref(0, Regs.RIP, 64)
		self.assertFalse(a.inst.operands[0].dispSize != 32)
		self.assertFalse(a.inst.operands[0].disp != 0x12345678)
	def test_reg8_rex(self):
		I64("mov sil, al").check_reg(0, Regs.SIL, 8)
		I64("inc bpl").check_reg(0, Regs.BPL, 8)
	def test_imm64(self):
		I64("mov rax, 0x1234567890abcdef").check_imm(1, 0x1234567890abcdef, 64)
	def test_reg64(self):
		I64("movsxd r10, eax").check_reg(0, Regs.R10, 64)
	def test_rm16_32_2(self):
		#MOVZXD RAX, [RAX]
		I64("db 0x63\n db 0x00").check_simple_deref(1, Regs.RAX, 32)
		#MOVZXDW RAX, [RAX]
		#I64("db 0x66\n db 0x63\n db 0x00").check_simple_deref(1, Regs.RAX, 16)
		#MOVZXD RAX, EAX
		I64("db 0x63\n db 0xc0").check_reg(1, Regs.EAX, 32)
		#MOVZXDW RAX, AX
		#I64("db 0x66\n db 0x63\n db 0xc0").check_reg(1, Regs.AX, 16)
		#MOVZXDW RAX, R8W
		#I64("db 0x66\n db 0x41\n db 0x63\n db 0xc0").check_reg(1, Regs.R8W, 16)
	Bases = ["RAX", "RCX", "RDX", "RBX", "RSP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
	BasesInfo = [Regs.RAX, Regs.RCX, Regs.RDX, Regs.RBX, Regs.RSP, Regs.RSI, Regs.RDI, Regs.R8, Regs.R9, Regs.R10, Regs.R11, Regs.R12, Regs.R13, Regs.R14, Regs.R15]
	Indices = ["RAX", "RCX", "RDX", "RBX", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
	IndicesInfo = [Regs.RAX, Regs.RCX, Regs.RDX, Regs.RBX, Regs.RBP, Regs.RSI, Regs.RDI, Regs.R8, Regs.R9, Regs.R10, Regs.R11, Regs.R12, Regs.R13, Regs.R14, Regs.R15]
	def test_bases(self):
		for i in enumerate(self.Bases):
			a = I64("cmp rbp, [%s]" % (i[1]))
			a.check_simple_deref(1, self.BasesInfo[i[0]], 64)
	def test_bases_disp32(self):
		for i in enumerate(self.Bases):
			a = I64("cmp rbp, [%s+0x12345678]" % (i[1]))
			a.check_simple_deref(1, self.BasesInfo[i[0]], 64)
			self.assertFalse(a.inst.operands[1].dispSize != 32)
			self.assertFalse(a.inst.operands[1].disp != 0x12345678)
	def test_scales(self):
		for i in enumerate(self.Indices):
			# A scale of 2 causes the scale to be omitted and changed from reg*2 to reg+reg.
			for s in [4, 8]:
				a = I64("and rbp, [%s*%d]" % (i[1], s))
				a.check_deref(1, self.IndicesInfo[i[0]], None, 64)
				self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I64("or rbp, [%s*%d + %s]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 64)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib_disp8(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I64("xor al, [%s*%d + %s + 0x55]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 8)
					self.assertFalse(a.inst.operands[1].dispSize != 8)
					self.assertFalse(a.inst.operands[1].disp != 0x55)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)
	def test_sib_disp32(self):
		for i in enumerate(self.Indices):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I64("sub rdx, [%s*%d + %s + 0x55aabbcc]" % (i[1], s, j[1]))
					a.check_deref(1, self.IndicesInfo[i[0]], self.BasesInfo[j[0]], 64)
					self.assertFalse(a.inst.operands[1].dispSize != 32)
					self.assertFalse(a.inst.operands[1].disp != 0x55aabbcc)
					if s != 1:
						self.assertFalse(a.inst.operands[1].scale != s)
	def test_base32(self):
		I64("mov eax, [ebx]").check_simple_deref(1, Regs.EBX, 32)

class TestInstTable(unittest.TestCase):
	""" Check that locate_inst algorithm covers all opcode-length (ol)
		for the varying sizes of opcodes.
		The bad tests should not find an instruction, so they should fail on purpose,
		to see we don't crash the diassembler.
		Also test for some end-cases with nop and wait. """
	def test_c7_opcode(self):
		IB32("c7f8aaaaaaaa").check_mnemonic("XBEGIN")
		IB64("c7f8aaaaaaaa").check_mnemonic("XBEGIN")
		IB32("C7C108000000").check_mnemonic("MOV")
		IB64("C7C108000000").check_mnemonic("MOV")
		IB64("48C7C000000000").check_mnemonic("MOV")
	def test_tx(self):
		IB64("0f01d5").check_mnemonic("XEND")
		IB64("c6f8bb").check_mnemonic("XABORT")
		IB64("c7f800000000").check_mnemonic("XBEGIN")
	def test_fuzz_9b_and_c7(self):
		for i in range(10000):
			s = "%02x%02x" % (i & 0xff, random.randint(0, 255))
			IB32("9b%sffffffff" % s)
			IB32("c7%sffffffff" % s)
	def test_ol1(self):
		IB32("00c0").check_mnemonic("ADD")
	def test_ol13(self):
		IB32("80c055").check_mnemonic("ADD")
	def test_ol1d(self):
		IB32("d900").check_mnemonic("FLD")
		IB32("d9c8").check_mnemonic("FXCH")
		IB32("d9e1").check_mnemonic("FABS")
	def test_ol2(self):
		IB32("0f06").check_mnemonic("CLTS")
	def test_ol23(self):
		IB32("0fbae055").check_mnemonic("BT")
	def test_ol2d(self):
		IB32("0f01e0").check_mnemonic("SMSW")
		IB32("0f0130").check_mnemonic("LMSW")
		IB32("0f01c9").check_mnemonic("MWAIT")
	def test_ol3(self):
		IB32("0f380000").check_mnemonic("PSHUFB")
	def test_ol1_bad(self):
		# There is no undefined instruction in the root, except a prefix, oh well.
		pass
	def test_ol13_bad(self):
		IB32("f780").check_invalid()
	def test_ol1d_bad(self):
		IB32("d908").check_invalid()
		IB32("d9d1").check_invalid()
		IB32("d9ef").check_invalid()
	def test_ol2_bad(self):
		IB32("0fff").check_invalid()
	def test_ol23_bad(self):
		IB32("0f0dff").check_invalid()
	def test_ol2d_bad(self):
		IB32("0f0128").check_invalid()
		IB32("0f01ca").check_invalid()
	def test_ol3_bad(self):
		IB32("0f0fff").check_invalid()
	def test_index63(self):
		# Test arpl, since it has a special treatment for 32/64 bits.
		a = IB32("63c0")
		a.check_mnemonic("ARPL")
		a = IB64("63c0")
		a.check_mnemonic("MOVSXD")
	def test_index90(self):
		# If nop is prefixed with f3, it is pause then. If it is prefixed with rex, it might be xchg.
		IB32("90").check_mnemonic("NOP")
		IB64("90").check_mnemonic("NOP")
		IB64("4890").check_mnemonic("NOP")
		IB64("4190").check_mnemonic("XCHG")
		IB64("f390").check_mnemonic("PAUSE")
	def test_wait(self):
		# Wait instruction is very tricky. It might be coalesced with the next bytes.
		# If the next bytes are 'waitable', otherwise it is a standalone instruction.
		IB32("9b90").check_mnemonic("WAIT", 0) # nop isn't waitable.
		IB32("9bdfe0").check_mnemonic("FSTSW") # waitable stsw
		IB32("dfe0").check_mnemonic("FNSTSW") # non-waitable stsw
		IB32("9b00c0").check_mnemonic("WAIT") # add isn't waitable
		IB32("9bd930").check_mnemonic("FSTENV") # waitable fstenv
		IB32("9b66dbe3").check_mnemonic("WAIT") # prefix breaks waiting
	def test_3dnow(self):
		IB32("0f0fc00d").check_mnemonic("PI2FD")
		IB32("0f0d00").check_mnemonic("PREFETCH")
	def test_mandatory(self):
		IB32("f30f10c0").check_mnemonic("MOVSS")
		IB32("660f10c0").check_mnemonic("MOVUPD")
		IB32("660f71d055").check_mnemonic("PSRLW")
		IB32("660ffec0").check_mnemonic("PADDD")
		IB32("f20f10c0").check_mnemonic("MOVSD")
		IB32("f20f11c0").check_mnemonic("MOVSD")
		IB32("660f3800c0").check_mnemonic("PSHUFB")
		IB32("f20f38f0c0").check_mnemonic("CRC32")
		IB32("660fc730").check_mnemonic("VMCLEAR")
		IB32("f30fc730").check_mnemonic("VMXON")
	def test_vex(self):
		I32("vaddpd ymm1, ymm2, ymm2").check_mnemonic("VADDPD") # pre encoding: 66, 0f, 58
		I32("vaddps ymm1, ymm2, ymm2").check_mnemonic("VADDPS") # pre encoding: 0f, 58
		I32("vaddsd xmm1, xmm2, qword [eax]").check_mnemonic("VADDSD") # pre encoding: f2, 0f, 58
		I32("vaddss xmm1, xmm2, dword [eax]").check_mnemonic("VADDSS") # pre encoding: f3, 0f, 58
		I32("vmovsd xmm1, xmm2, xmm3").check_mnemonic("VMOVSD") # pre encoding: f2, 0f, 10
		I32("vmovsd xmm1, qword [eax]").check_mnemonic("VMOVSD") # pre encoding: f2 0f 10 - but VEX.vvvv is not encoded!
		# Since in a VEX prefix you can encode the virtual prefix, we got three ways to get to 0xf 0x38
		# So see that both work well.
		IB32("c4e279dbc2").check_mnemonic("VAESIMC") # pre encoding: 66, 0f, 38, db, virtual prefix is 0f 38
		IB32("c4e17938dbc2").check_mnemonic("VAESIMC") # the virtual prefix is only 0f
		IB32("c5f938dbc2").check_mnemonic("VAESIMC") # the virtual prefix is only 0f, but short VEX
		# Same test as earlier, but for 0xf 0x3a, though this instruction doesn't have a short form.
		IB32("c4e3710dc255").check_mnemonic("VBLENDPD") # pre encoding: 66, 0f, 3a, 0d, virtual prefix is 0f 3a
		IB32("c4e1713a0dc255").check_mnemonic("VBLENDPD") # pre encoding: 66, 0f, 3a, 0d, virtual prefix is 0f
		I32("vldmxcsr dword [eax]").check_mnemonic("VLDMXCSR")
		I32("vzeroupper").check_mnemonic("VZEROUPPER")
		I32("vzeroall").check_mnemonic("VZEROALL")
		I32("vpslld xmm1, xmm2, xmm3").check_mnemonic("VPSLLD")
	def test_vex_special(self):
		# VVVV encoded, where there is not such an encoding for the VAESIMC instruction.
		IB32("c4e271dbca").check_invalid()
		IB32("c4e2791800").check_mnemonic("VBROADCASTSS") # just to make sure this instruction is fine.
		IB32("c4e279ff00").check_invalid() # pre encoding: 66, 0f, 38, ff
		IB32("c4e179ff00").check_invalid() # pre encoding: 66, 0f, 38, ff, mmmmm = 1
		IB32("c4e379ff00").check_invalid() # pre encoding: 66, 0f, 38, ff, mmmmm = 3
		IB32("c4e4791800").check_invalid() # pre encoding: 66, 0f, 38, 18, mmmmm = 4
		IB32("c5f8ae10").check_mnemonic("VLDMXCSR") # pre encoding: 0f, ae /02
		IB32("c4c178ae10").check_mnemonic("VLDMXCSR") # longer form of 0f, ae /02
		IB32("c4c179ae10").check_invalid() # longer form of 0f, ae /02, invalid pp=1
		IB32("c4c17aae10").check_invalid() # longer form of 0f, ae /02, invalid pp=2
		IB32("c4c17bae10").check_invalid() # longer form of 0f, ae /02, invalid pp=3
		IB32("c4c17877").check_mnemonic("VZEROUPPER") # longer form of 0f, 77
		IB32("c4c17c77").check_mnemonic("VZEROALL") # longer form of 0f, 77
		IB32("c4c97c77").check_invalid() # longer form of 0f, 77, invalid mmmmm
	def test_crc32(self):
		I32("crc32 eax, al").check_reg(0, Regs.EAX, 32)
	def test_lzcnt(self):
		# This is the only instruction that has a mandatory prefix and can have ALSO a valid operand size prefix!
		I32("lzcnt ax, bx").check_reg(0, Regs.AX, 16)
		I32("lzcnt eax, ebx").check_reg(0, Regs.EAX, 32)
		I64("lzcnt rax, rbx").check_reg(0, Regs.RAX, 64)

class TestAVXOperands(unittest.TestCase):
	def test_rm32(self):
		#I16("vextractps eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I32("vextractps eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I64("vextractps eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
	def test_reg32_64_m8(self):
		#I16("vpextrb eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I32("vpextrb eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I64("vpextrb eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I64("vpextrb rax, xmm2, 3").check_reg(0, Regs.RAX, 64)
		I32("vpextrb [ebx], xmm2, 3").check_simple_deref(0, Regs.EBX, 8)
		I64("vpextrb [rbx], xmm2, 3").check_simple_deref(0, Regs.RBX, 8)
	def test_reg32_64_m16(self):
		I32("vpextrw eax, xmm2, 3").check_reg(0, Regs.EAX, 32)
		I64("vpextrw rax, xmm2, 3").check_reg(0, Regs.RAX, 64)
		I64("vpextrw rax, xmm2, 3").check_reg(0, Regs.RAX, 64)
		I32("vpextrw [ebx], xmm2, 3").check_simple_deref(0, Regs.EBX, 16)
		I64("vpextrw [rbx], xmm2, 3").check_simple_deref(0, Regs.RBX, 16)
	def test_wreg32_64_WITH_wxmm32_64(self):
		a = I32("vcvtss2si eax, xmm1")
		a.check_reg(0, Regs.EAX, 32)
		a.check_reg(1, Regs.XMM1, 128)
		a = I64("vcvtss2si rax, [rbx]")
		a.check_reg(0, Regs.RAX, 64)
		a.check_simple_deref(1, Regs.RBX, 64)
		a = I64("vcvtss2si eax, [rbx]")
		a.check_reg(0, Regs.EAX, 32)
		a.check_simple_deref(1, Regs.RBX, 32)
	def test_vxmm(self):
		I32("vaddsd xmm1, xmm2, xmm3").check_reg(1, Regs.XMM2, 128)
		I64("vaddsd xmm2, xmm3, xmm4").check_reg(1, Regs.XMM3, 128)
	def test_xmm_imm(self):
		I32("vpblendvb xmm1, xmm2, xmm3, xmm4").check_reg(3, Regs.XMM4, 128)
		# Force XMM15, but high bit is ignored in 32bits.
		self.assertFalse(IB32("c4e3694ccbf0").inst.operands[3].index != Regs.XMM7)
		I64("vpblendvb xmm1, xmm2, xmm3, xmm15").check_reg(3, Regs.XMM15, 128)
	def test_yxmm(self):
		I32("vaddsubpd ymm2, ymm4, ymm6").check_reg(0, Regs.YMM2, 256)
		I32("vaddsubpd xmm7, xmm4, xmm6").check_reg(0, Regs.XMM7, 128)
		I64("vaddsubpd ymm12, ymm4, ymm6").check_reg(0, Regs.YMM12, 256)
		I64("vaddsubpd xmm14, xmm4, xmm6").check_reg(0, Regs.XMM14, 128)
	def test_yxmm_imm(self):
		I32("vblendvpd xmm1, xmm2, xmm3, xmm4").check_reg(3, Regs.XMM4, 128)
		I32("vblendvpd ymm1, ymm2, ymm3, ymm4").check_reg(3, Regs.YMM4, 256)
		# Force YMM15, but high bit is ignored in 32bits.
		self.assertFalse(IB32("c4e36d4bcbf0").inst.operands[3].index != Regs.YMM7)
		I64("vblendvpd xmm1, xmm2, xmm3, xmm14").check_reg(3, Regs.XMM14, 128)
		I64("vblendvpd ymm1, ymm2, ymm3, ymm9").check_reg(3, Regs.YMM9, 256)
	def test_ymm(self):
		I32("vbroadcastsd ymm5, [eax]").check_reg(0, Regs.YMM5, 256)
		I64("vbroadcastsd ymm13, [rax]").check_reg(0, Regs.YMM13, 256)
	def test_ymm256(self):
		I32("vperm2f128 ymm2, ymm4, [eax], 0x55").check_simple_deref(2, Regs.EAX, 256)
		I64("vperm2f128 ymm2, ymm14, [rax], 0x55").check_simple_deref(2, Regs.RAX, 256)
	def test_vymm(self):
		I32("vinsertf128 ymm1, ymm4, xmm4, 0xaa").check_reg(1, Regs.YMM4, 256)
		I64("vinsertf128 ymm1, ymm15, xmm4, 0xaa").check_reg(1, Regs.YMM15, 256)
	def test_vyxmm(self):
		I32("vmaxpd xmm1, xmm2, xmm3").check_reg(1, Regs.XMM2, 128)
		I32("vmaxpd ymm1, ymm2, ymm3").check_reg(1, Regs.YMM2, 256)
		I64("vmaxpd xmm1, xmm12, xmm3").check_reg(1, Regs.XMM12, 128)
		I64("vmaxpd ymm1, ymm12, ymm3").check_reg(1, Regs.YMM12, 256)
	def test_yxmm64_256(self):
		I32("vmovddup xmm1, xmm2").check_reg(1, Regs.XMM2, 128)
		I32("vmovddup ymm1, ymm2").check_reg(1, Regs.YMM2, 256)
		I32("vmovddup xmm1, [ecx]").check_simple_deref(1, Regs.ECX, 64)
		I32("vmovddup ymm1, [ebx]").check_simple_deref(1, Regs.EBX, 256)
		I64("vmovddup xmm1, xmm12").check_reg(1, Regs.XMM12, 128)
		I64("vmovddup ymm1, ymm12").check_reg(1, Regs.YMM12, 256)
		I64("vmovddup xmm1, [rcx]").check_simple_deref(1, Regs.RCX, 64)
		I64("vmovddup ymm1, [rbx]").check_simple_deref(1, Regs.RBX, 256)
	def test_yxmm128_256(self):
		I32("vandnpd xmm1, xmm2, xmm3").check_reg(2, Regs.XMM3, 128)
		I32("vandnpd ymm1, ymm2, ymm3").check_reg(2, Regs.YMM3, 256)
		I32("vandnpd xmm1, xmm2, [edi]").check_simple_deref(2, Regs.EDI, 128)
		I32("vandnpd ymm1, ymm2, [esi]").check_simple_deref(2, Regs.ESI, 256)
		I64("vandnpd xmm1, xmm2, xmm13").check_reg(2, Regs.XMM13, 128)
		I64("vandnpd ymm1, ymm2, ymm13").check_reg(2, Regs.YMM13, 256)
		I64("vandnpd xmm1, xmm2, [rdi]").check_simple_deref(2, Regs.RDI, 128)
		I64("vandnpd ymm1, ymm2, [rsi]").check_simple_deref(2, Regs.RSI, 256)
	def test_lxmm64_128(self):
		I32("vcvtdq2pd xmm1, xmm2").check_reg(1, Regs.XMM2, 128)
		I32("vcvtdq2pd xmm1, [eax]").check_simple_deref(1, Regs.EAX, 64)
		I32("vcvtdq2pd ymm1, [ebx]").check_simple_deref(1, Regs.EBX, 128)
		I64("vcvtdq2pd xmm1, xmm12").check_reg(1, Regs.XMM12, 128)
		I64("vcvtdq2pd xmm1, [rax]").check_simple_deref(1, Regs.RAX, 64)
		I64("vcvtdq2pd ymm1, [rbx]").check_simple_deref(1, Regs.RBX, 128)
	def test_lmem128_256(self):
		I32("vlddqu xmm1, [eax]").check_simple_deref(1, Regs.EAX, 128)
		I32("vlddqu ymm1, [eax]").check_simple_deref(1, Regs.EAX, 256)
		I64("vlddqu xmm1, [r14]").check_simple_deref(1, Regs.R14, 128)
		I64("vlddqu ymm1, [r13]").check_simple_deref(1, Regs.R13, 256)

class TestMisc(unittest.TestCase):
	def test_lods(self):
		a = I16("lodsb")
		a.check_reg(0, Regs.AL, 8)
		a.check_simple_deref(1, Regs.SI, 8)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("lodsw")
		a.check_reg(0, Regs.AX, 16)
		a.check_simple_deref(1, Regs.ESI, 16)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("lodsd")
		a.check_reg(0, Regs.EAX, 32)
		a.check_simple_deref(1, Regs.ESI, 32)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I64("lodsq")
		a.check_reg(0, Regs.RAX, 64)
		a.check_simple_deref(1, Regs.RSI, 64)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I16("db 0x2e\nlodsb")
		a.check_reg(0, Regs.AL, 8)
		a.check_simple_deref(1, Regs.SI, 8)
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I32("db 0x2e\nlodsw")
		a.check_reg(0, Regs.AX, 16)
		a.check_simple_deref(1, Regs.ESI, 16)
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I32("db 0x2e\nlodsd")
		a.check_reg(0, Regs.EAX, 32)
		a.check_simple_deref(1, Regs.ESI, 32)
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I64("db 0x65\nlodsq")
		a.check_reg(0, Regs.RAX, 64)
		a.check_simple_deref(1, Regs.RSI, 64)
		self.assertEqual(a.inst.segment, Regs.GS)
		self.assertEqual(a.inst.isSegmentDefault, False)
	def test_stos(self):
		a = I16("stosb")
		a.check_simple_deref(0, Regs.DI, 8)
		a.check_reg(1, Regs.AL, 8)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("stosw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_reg(1, Regs.AX, 16)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("stosd")
		a.check_simple_deref(0, Regs.EDI, 32)
		a.check_reg(1, Regs.EAX, 32)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I64("stosq")
		a.check_simple_deref(0, Regs.RDI, 64)
		a.check_reg(1, Regs.RAX, 64)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I16("db 0x2e\nstosb")
		a.check_simple_deref(0, Regs.DI, 8)
		a.check_reg(1, Regs.AL, 8)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("db 0x2e\nstosw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_reg(1, Regs.AX, 16)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("db 0x2e\nstosd")
		a.check_simple_deref(0, Regs.EDI, 32)
		a.check_reg(1, Regs.EAX, 32)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I64("db 0x65\nstosq")
		a.check_simple_deref(0, Regs.RDI, 64)
		a.check_reg(1, Regs.RAX, 64)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, REG_NONE)
	def test_scas(self):
		a = I16("scasb")
		a.check_simple_deref(0, Regs.DI, 8)
		a.check_reg(1, Regs.AL, 8)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("scasw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_reg(1, Regs.AX, 16)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("scasd")
		a.check_simple_deref(0, Regs.EDI, 32)
		a.check_reg(1, Regs.EAX, 32)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I64("scasq")
		a.check_simple_deref(0, Regs.RDI, 64)
		a.check_reg(1, Regs.RAX, 64)
		self.assertEqual(a.inst.isSegmentDefault, False)
		a = I16("db 0x2e\nscasb")
		a.check_simple_deref(0, Regs.DI, 8)
		a.check_reg(1, Regs.AL, 8)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("db 0x2e\nscasw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_reg(1, Regs.AX, 16)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("db 0x2e\nscasd")
		a.check_simple_deref(0, Regs.EDI, 32)
		a.check_reg(1, Regs.EAX, 32)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I64("db 0x65\nscasq")
		a.check_simple_deref(0, Regs.RDI, 64)
		a.check_reg(1, Regs.RAX, 64)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, REG_NONE)
	def test_cmps(self):
		a = I64("cmpsd")
		a.check_simple_deref(0, Regs.RSI, 32)
		a.check_simple_deref(1, Regs.RDI, 32)
		self.assertEqual(a.inst.unusedPrefixesMask, 0)
		self.assertEqual(a.inst.segment, REG_NONE)
		a = I16("db 0x2e\ncmpsb")
		a.check_simple_deref(0, Regs.SI, 8)
		a.check_simple_deref(1, Regs.DI, 8)
		self.assertEqual(a.inst.unusedPrefixesMask, 0)
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
	def test_movs(self):
		a = I32("movsd")
		a.check_simple_deref(0, Regs.EDI, 32)
		a.check_simple_deref(1, Regs.ESI, 32)
		self.assertEqual(a.inst.unusedPrefixesMask, 0)
		self.assertEqual(a.inst.segment, Regs.DS)
		self.assertEqual(a.inst.isSegmentDefault, True)
		a = I32("db 0x2e\nmovsw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_simple_deref(1, Regs.ESI, 16)
		self.assertEqual(a.inst.unusedPrefixesMask, 0)
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
	def test_ins(self):
		a = I32("db 0x65\ninsw")
		a.check_simple_deref(0, Regs.EDI, 16)
		a.check_reg(1, Regs.DX, 16)
		self.assertEqual(a.inst.unusedPrefixesMask, 1)
		self.assertEqual(a.inst.segment, Regs.ES)
		self.assertEqual(a.inst.isSegmentDefault, True)
	def test_outs(self):
		a = I64("db 0x65\noutsd")
		a.check_reg(0, Regs.DX, 16)
		a.check_simple_deref(1, Regs.RSI, 32)
		self.assertEqual(a.inst.segment, Regs.GS)
		self.assertEqual(a.inst.isSegmentDefault, False)
	def test_branch_hints(self):
		self.assertFalse("FLAG_HINT_TAKEN" not in I32("db 0x3e\n jnz 0x50").inst.flags)
		self.assertFalse("FLAG_HINT_NOT_TAKEN" not in I32("db 0x2e\n jp 0x55").inst.flags)
		self.assertFalse("FLAG_HINT_NOT_TAKEN" not in I32("db 0x2e\n jo 0x55000").inst.flags)
		self.assertFalse(I32("db 0x2e\n loop 0x55").inst.rawFlags & 0x1f, 0)
	def test_mnemonic_by_vexw(self):
		I32("vmovd xmm1, eax").check_mnemonic("VMOVD")
		I64("vmovd xmm1, eax").check_reg(1, Regs.EAX, 32)
		a = I64("vmovq xmm1, rax")
		a.check_mnemonic("VMOVQ")
		a.check_reg(1, Regs.RAX, 64)
	def test_vexl_ignored(self):
		I32("vaesdeclast xmm1, xmm2, xmm3").check_reg(0, Regs.XMM1, 128)
		IB32("c4e26ddfcb").check_mnemonic("VAESDECLAST")
		IB64("c4e26ddfcb").check_mnemonic("VAESDECLAST")
	def test_vexl_needed(self):
		I32("vinsertf128 ymm1, ymm2, xmm4, 0x42").check_mnemonic("VINSERTF128")
		IB32("c4e36918cc42").check_invalid() # Without VEX.L.
		IB64("c4e36918cc42").check_invalid() # Without VEX.L.
	def test_force_reg0(self):
		I32("extrq xmm1, 0x55, 0x66").check_mnemonic("EXTRQ")
		I64("extrq xmm14, 0x55, 0x66").check_reg(0, Regs.XMM14, 128)
	def test_pause(self):
		self.assertEqual(I16("pause").inst.size, 2)
		self.assertEqual(I32("pause").inst.size, 2)
		self.assertEqual(I64("pause").inst.size, 2)
	def test_nop(self):
		self.assertEqual(I16("db 0x90").inst.size, 1)
		self.assertEqual(I32("db 0x90").inst.size, 1)
		self.assertEqual(I64("db 0x90").inst.size, 1)
		self.assertEqual(I64("db 0x48, 0x90").inst.size, 2)
		# XCHG R8D, EAX
		a = I64("db 0x41, 0x90")
		a.check_reg(0, Regs.R8D, 32)
		a.check_reg(1, Regs.EAX, 32)
		# XCHG R8, RAX
		a = I64("db 0x49, 0x90")
		a.check_reg(0, Regs.R8, 64)
		a.check_reg(1, Regs.RAX, 64)
		a = I64("db 0x4f, 0x90")
		a.check_reg(0, Regs.R8, 64)
		a.check_reg(1, Regs.RAX, 64)
	def test_3dnow(self):
		I32("pfadd mm4, [eax]").check_reg(0, Regs.MM4, 64)
		I32("pfsub mm5, [eax]").check_reg(0, Regs.MM5, 64)
		I32("pfrcpit1 mm1, [ebx]").check_mnemonic("PFRCPIT1")
		I64("pavgusb mm1, mm2").check_mnemonic("PAVGUSB")
	def test_all_segs(self):
		I16("push fs").check_reg(0, Regs.FS, 16)
		I16("push gs").check_reg(0, Regs.GS, 16)
		I16("push ds").check_reg(0, Regs.DS, 16)
		I16("push cs").check_reg(0, Regs.CS, 16)
		I16("push ds").check_reg(0, Regs.DS, 16)
		I16("push es").check_reg(0, Regs.ES, 16)
	def test_op4(self):
		a = I32("insertq xmm2, xmm1, 0x55, 0xaa")
		a.check_reg(0, Regs.XMM2, 128)
		a.check_reg(1, Regs.XMM1, 128)
		a.check_type_size(2, distorm3.OPERAND_IMMEDIATE, 8)
		self.assertEqual(a.inst.operands[2].value, 0x55)
		a.check_type_size(3, distorm3.OPERAND_IMMEDIATE, 8)
		self.assertEqual(a.inst.operands[3].value, 0xaa)
	def test_pseudo_cmp(self):
		I32("cmpps xmm2, xmm3, 0x7")
		I64("cmpps xmm2, xmm4, 0x2")
	def test_jmp_counters(self):
		I16("jcxz 0x100")
		I32("jecxz 0x100")
		I64("jrcxz 0x100")
	def test_natives(self):
		self.assertEqual(I16("pusha").inst.size, 1)
		self.assertEqual(I16("pushad").inst.size, 2)
		self.assertEqual(I32("pusha").inst.size, 1)
		self.assertEqual(I32("pushaw").inst.size, 2)
		self.assertEqual(I16("CBW").inst.size, 1)
		self.assertEqual(I32("CWDE").inst.size, 1)
		self.assertEqual(I64("CDQE").inst.size, 2)
	def test_modrm_based(self):
		I32("movhlps xmm0, xmm1")
		I32("movhps xmm0, [eax]")
		I64("movhlps xmm0, xmm1")
		I64("movhps xmm0, [eax]")
		I64("movhlps xmm0, xmm1")
		I64("movlps xmm0, [eax]")
	def test_wait(self):
		self.assertEqual(I16("wait").inst.size, 1)
	def test_include_wait(self):
		self.assertEqual(I16("db 0x9b\n db 0xd9\n db 0x30").inst.size, 3)
	def test_loopxx_counters_size(self):
		a = I16("loopz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(16)
		a = I32("loopz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(32)
		a = I64("loopz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(64)
		a = I16("db 0x67\n loopz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(32)
		a = I32("db 0x67\n loopz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(16)
		a = I64("db 0x67\n loopnz 0x50")
		a.check_type_size(0,distorm3.OPERAND_IMMEDIATE, 8)
		a.check_addr_size(32)
	def test_privileged(self):
		self.assertFalse(IB32("90").inst.privileged)
		self.assertTrue(I32("iret").inst.privileged)

def _hexlify(data):
	s = ""
	if type(data[0]) == str: # Python 2.x
		for i in data:
			s += "%02x" % ord(i)
	else:
		for i in data: # Python 3.x
			s += "%02x" % i
	return s

class TestMisc2(unittest.TestCase):
	def test_binary(self):
		# Generate 128kb of random bytes.
		# Disasm them, extract the returned hex,
		# And see that it matches the input.
		# This checks no bytes are skipped.
		data = "".join(["%02x" % random.randint(0, 255) for i in range(1 << 17)])
		insts = IB16(data).insts
		output = "".join([_hexlify(i.instructionBytes) for i in insts])
		self.assertTrue(data == output)
		insts = IB32(data).insts
		output = "".join([_hexlify(i.instructionBytes) for i in insts])
		self.assertTrue(data == output)
		insts = IB64(data).insts
		output = "".join([_hexlify(i.instructionBytes) for i in insts])
		self.assertTrue(data == output)
	def test_longest_mnemonic(self):
		# The longest mnemonic is VAESKEYGENASSIST and check it's null terminated.
		self.assertEqual(I32("VAESKEYGENASSIST xmm1, xmm2, 7").inst.mnemonic, "VAESKEYGENASSIST")

class TestPrefixes(unittest.TestCase):
	Derefs16 = ["BX + SI", "BX + DI", "BP + SI", "BP + DI", "SI", "DI", "BP", "BX"]
	Derefs32 = ["EAX", "ECX", "EDX", "EBX", "EBP", "ESI", "EDI"]
	Bases = ["EAX", "ECX", "EDX", "EBX", "ESP", "ESI", "EDI"]
	def test_without_seg(self):
		self.assertEqual(I64("and [rip+0X5247], ch").inst.segment, REG_NONE)
		self.assertEqual(I32("mov eax, [ebp*4]").inst.segment, Regs.DS)
		self.assertEqual(I32("mov eax, [eax*4+ebp]").inst.segment, Regs.SS)
	def test_default_seg16(self):
		a = I16("mov [ds:0x1234], ax")
		self.assertEqual(a.inst.segment, Regs.DS)
		self.assertEqual(a.inst.isSegmentDefault, 1)
		a = I16("mov [cs:0x1234], ax")
		self.assertEqual(a.inst.segment, Regs.CS)
		self.assertEqual(a.inst.isSegmentDefault, False)
	def test_default_seg16_all(self):
		for i in ["ADD [ds:%s], AX" % i for i in self.Derefs16]:
			a = I16(i)
			self.assertEqual(a.inst.segment, Regs.DS)
			if i[8:10] == "BP":
				self.assertEqual(a.inst.isSegmentDefault, False)
			else:
				self.assertEqual(a.inst.isSegmentDefault, True)
		# Test with disp8
		for i in ["ADD [ds:%s + 0x55], AX" % i for i in self.Derefs16]:
			a = I16(i)
			self.assertEqual(a.inst.segment, Regs.DS)
			if i[8:10] == "BP":
				self.assertEqual(a.inst.isSegmentDefault, False)
			else:
				self.assertEqual(a.inst.isSegmentDefault, True)
	def test_default_seg32(self):
		self.assertEqual(I32("mov [ds:0x12345678], eax").inst.segment, Regs.DS)
		self.assertEqual(I32("mov [cs:0x12345678], eax").inst.segment, Regs.CS)
		texts = ["ADD [ds:%s], EAX" % i for i in self.Derefs32]
		for i in enumerate(texts):
			a = I32(i[1])
			self.assertEqual(a.inst.segment, Regs.DS)
			if self.Derefs32[i[0]] == "EBP":
				self.assertEqual(a.inst.isSegmentDefault, False)
			else:
				self.assertEqual(a.inst.isSegmentDefault, True)
		# Test with disp8
		texts = ["ADD [ds:%s + 0x55], EAX" % i for i in self.Derefs32]
		for i in enumerate(texts):
			a = I32(i[1])
			self.assertEqual(a.inst.segment, Regs.DS)
			if self.Derefs32[i[0]] == "EBP":
				self.assertEqual(a.inst.isSegmentDefault, False)
			else:
				self.assertEqual(a.inst.isSegmentDefault, True)
	def test_sib(self):
		for i in enumerate(self.Derefs32):
			for j in enumerate(self.Bases):
				for s in [1, 2, 4, 8]:
					a = I32("cmp ebp, [ds:%s*%d + %s]" % (i[1], s, j[1]))
					a2 = I32("cmp ebp, [ds:%s*%d + %s + 0x55]" % (i[1], s, j[1]))
					self.assertEqual(a.inst.segment, Regs.DS)
					self.assertEqual(a2.inst.segment, Regs.DS)
					if (j[1] == "EBP" or j[1] == "ESP"):
						self.assertEqual(a.inst.isSegmentDefault, False)
						self.assertEqual(a2.inst.isSegmentDefault, False)
					else:
						self.assertEqual(a.inst.isSegmentDefault, True)
						self.assertEqual(a2.inst.isSegmentDefault, True)

	def test_seg64(self):
		self.assertEqual(I64("mov [gs:rip+0x12345678], eax").inst.segment, Regs.GS)
		self.assertEqual(I64("mov [fs:0x12345678], eax").inst.segment, Regs.FS)
	def test_lock(self):
		self.assertFalse("FLAG_LOCK" not in I32("lock inc dword [eax]").inst.flags)
	def test_repnz(self):
		self.assertFalse("FLAG_REPNZ" not in I32("repnz scasb").inst.flags)
	def test_rep(self):
		self.assertFalse("FLAG_REP" not in I32("rep movsb").inst.flags)
	def test_reps(self):
		""" Scas and cmps have different repZ prefix. """
		self.assertTrue(str(I32("rep scasb").inst).find("REPZ") != -1)
		self.assertTrue(str(I32("rep cmpsd").inst).find("REPZ") != -1)
		self.assertTrue(str(I32("rep stosb").inst).find("REP") != -1)
		self.assertTrue(str(I32("rep stosb").inst).find("REPZ") == -1)
		self.assertTrue(str(I16("repnz scasb").inst).find("REPNZ") != -1)
		self.assertTrue(str(I32("repnz cmpsd").inst).find("REPNZ") != -1)
		self.assertTrue(str(I64("repnz stosb").inst).find("REPNZ") != -1)
	def test_stos(self):
		""" STOS instruction is treated specially with certain prefixes, check all such cases. """
		# 16 bits
		self.assertEqual(str(IB16("aa").inst), "STOSB")
		self.assertEqual(str(IB16("ab").inst), "STOSW")
		self.assertEqual(str(IB16("66ab").inst), "STOSD")
		self.assertEqual(str(IB16("67ab").inst), "STOS [EDI], AX")
		self.assertEqual(str(IB16("6766ab").inst), "STOS [EDI], EAX")
		self.assertEqual(str(IB16("2eab").inst), "STOSW") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB16("f3ab").inst), "REP STOSW")
		self.assertEqual(str(IB16("f2ab").inst), "REPNZ STOSW")
		# 32 bits
		self.assertEqual(str(IB32("aa").inst), "STOSB")
		self.assertEqual(str(IB32("ab").inst), "STOSD")
		self.assertEqual(str(IB32("66ab").inst), "STOSW")
		self.assertEqual(str(IB32("67ab").inst), "STOS [DI], EAX")
		self.assertEqual(str(IB32("6766ab").inst), "STOS [DI], AX")
		self.assertEqual(str(IB32("2eab").inst), "STOSD") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB32("f3ab").inst), "REP STOSD")
		self.assertEqual(str(IB32("f2ab").inst), "REPNZ STOSD")
		# 64 bits
		self.assertEqual(str(IB64("aa").inst), "STOSB")
		self.assertEqual(str(IB64("ab").inst), "STOSD")
		self.assertEqual(str(IB64("48ab").inst), "STOSQ")
		self.assertEqual(str(IB64("66ab").inst), "STOSW")
		self.assertEqual(str(IB64("67ab").inst), "STOS [EDI], EAX")
		self.assertEqual(str(IB64("6766ab").inst), "STOS [EDI], AX")
		self.assertEqual(str(IB64("2eab").inst), "STOSD") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB64("2e48ab").inst), "STOSQ") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB64("f3ab").inst), "REP STOSD")
		self.assertEqual(str(IB64("f348ab").inst), "REP STOSQ")
		self.assertEqual(str(IB64("f2ab").inst), "REPNZ STOSD")
		self.assertEqual(str(IB64("f248ab").inst), "REPNZ STOSQ")
	def test_scas(self):
		""" SCAS instruction is treated specially with certain prefixes, check all such cases. """
		# 16 bits
		self.assertEqual(str(IB16("ae").inst), "SCASB")
		self.assertEqual(str(IB16("af").inst), "SCASW")
		self.assertEqual(str(IB16("66af").inst), "SCASD")
		self.assertEqual(str(IB16("67af").inst), "SCAS [EDI], AX")
		self.assertEqual(str(IB16("6766af").inst), "SCAS [EDI], EAX")
		self.assertEqual(str(IB16("2eaf").inst), "SCASW") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB16("f3af").inst), "REPZ SCASW")
		self.assertEqual(str(IB16("f2af").inst), "REPNZ SCASW")
		# 32 bits
		self.assertEqual(str(IB32("ae").inst), "SCASB")
		self.assertEqual(str(IB32("af").inst), "SCASD")
		self.assertEqual(str(IB32("66af").inst), "SCASW")
		self.assertEqual(str(IB32("67af").inst), "SCAS [DI], EAX")
		self.assertEqual(str(IB32("6766af").inst), "SCAS [DI], AX")
		self.assertEqual(str(IB32("2eaf").inst), "SCASD") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB32("f3af").inst), "REPZ SCASD")
		self.assertEqual(str(IB32("f2af").inst), "REPNZ SCASD")
		# 64 bits
		self.assertEqual(str(IB64("ae").inst), "SCASB")
		self.assertEqual(str(IB64("af").inst), "SCASD")
		self.assertEqual(str(IB64("48af").inst), "SCASQ")
		self.assertEqual(str(IB64("66af").inst), "SCASW")
		self.assertEqual(str(IB64("67af").inst), "SCAS [EDI], EAX")
		self.assertEqual(str(IB64("6766af").inst), "SCAS [EDI], AX")
		self.assertEqual(str(IB64("2eaf").inst), "SCASD") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB64("2e48af").inst), "SCASQ") # 1st op cannot be prefixed by segment!
		self.assertEqual(str(IB64("f3af").inst), "REPZ SCASD")
		self.assertEqual(str(IB64("f348af").inst), "REPZ SCASQ")
		self.assertEqual(str(IB64("f2af").inst), "REPNZ SCASD")
		self.assertEqual(str(IB64("f248af").inst), "REPNZ SCASQ")
	def test_lods(self):
		""" LODS instruction is treated specially with certain prefixes, check all such cases. """
		# 16 bits
		self.assertEqual(str(IB16("ac").inst), "LODSB")
		self.assertEqual(str(IB16("ad").inst), "LODSW")
		self.assertEqual(str(IB16("66ad").inst), "LODSD")
		self.assertEqual(str(IB16("67ad").inst), "LODS AX, [ESI]")
		self.assertEqual(str(IB16("6766ad").inst), "LODS EAX, [ESI]")
		self.assertEqual(str(IB16("64ad").inst), "LODS AX, [FS:SI]")
		self.assertEqual(str(IB16("f364ad").inst), "REP LODS AX, [FS:SI]")
		self.assertEqual(str(IB16("f264ad").inst), "REPNZ LODS AX, [FS:SI]")
		# 32 bits
		self.assertEqual(str(IB32("ac").inst), "LODSB")
		self.assertEqual(str(IB32("66ad").inst), "LODSW")
		self.assertEqual(str(IB32("ad").inst), "LODSD")
		self.assertEqual(str(IB32("f3ac").inst), "REP LODSB")
		self.assertEqual(str(IB32("66f3ad").inst), "REP LODSW")
		self.assertEqual(str(IB32("f3ad").inst), "REP LODSD")
		self.assertEqual(str(IB32("65ad").inst), "LODS EAX, [GS:ESI]")
		self.assertEqual(str(IB32("f365ad").inst), "REP LODS EAX, [GS:ESI]")
		self.assertEqual(str(IB32("f36567ad").inst), "REP LODS EAX, [GS:SI]")
		self.assertEqual(str(IB32("f3656766ad").inst), "REP LODS AX, [GS:SI]")
		self.assertEqual(str(IB32("6667f365ad").inst), "REP LODS AX, [GS:SI]")
		self.assertEqual(str(IB32("67f3ac").inst), "REP LODS AL, [SI]")
		self.assertEqual(str(IB32("67f2ac").inst), "REPNZ LODS AL, [SI]")
		# 64 bits
		self.assertEqual(str(IB64("ac").inst), "LODSB")
		self.assertEqual(str(IB64("66ad").inst), "LODSW")
		self.assertEqual(str(IB64("ad").inst), "LODSD")
		self.assertEqual(str(IB64("48ad").inst), "LODSQ")
		self.assertEqual(str(IB64("f3ac").inst), "REP LODSB")
		self.assertEqual(str(IB64("66f3ad").inst), "REP LODSW")
		self.assertEqual(str(IB64("f3ad").inst), "REP LODSD")
		self.assertEqual(str(IB64("65ad").inst), "LODS EAX, [GS:RSI]")
		self.assertEqual(str(IB64("f365ad").inst), "REP LODS EAX, [GS:RSI]")
		self.assertEqual(str(IB64("f36567ad").inst), "REP LODS EAX, [GS:ESI]")
		self.assertEqual(str(IB64("f3656766ad").inst), "REP LODS AX, [GS:ESI]")
		self.assertEqual(str(IB64("6667f365ad").inst), "REP LODS AX, [GS:ESI]")
		self.assertEqual(str(IB64("6667f265ad").inst), "REPNZ LODS AX, [GS:ESI]")
		self.assertEqual(str(IB64("67f3ac").inst), "REP LODS AL, [ESI]")
	def test_movs(self):
		""" MOVS instruction is treated specially with certain prefixes, check all such cases. """
		# 16 bits
		self.assertEqual(str(IB16("a4").inst), "MOVSB")
		self.assertEqual(str(IB16("66a5").inst), "MOVSD")
		self.assertEqual(str(IB16("a5").inst), "MOVSW")
		self.assertEqual(str(IB16("f3a5").inst), "REP MOVSW")
		self.assertEqual(str(IB16("66f3a5").inst), "REP MOVSD")
		self.assertEqual(str(IB16("f366a5").inst), "REP MOVSD")
		self.assertEqual(str(IB16("f3a5").inst), "REP MOVSW")
		self.assertEqual(str(IB16("65a5").inst), "MOVS WORD [ES:DI], [GS:SI]")
		self.assertEqual(str(IB16("f365a5").inst), "REP MOVS WORD [ES:DI], [GS:SI]")
		self.assertEqual(str(IB16("f36567a5").inst), "REP MOVS WORD [ES:EDI], [GS:ESI]")
		self.assertEqual(str(IB16("f3656766a5").inst), "REP MOVS DWORD [ES:EDI], [GS:ESI]")
		self.assertEqual(str(IB16("6667f365a5").inst), "REP MOVS DWORD [ES:EDI], [GS:ESI]")
		self.assertEqual(str(IB16("6667f3a4").inst), "REP MOVS BYTE [ES:EDI], [DS:ESI]")
		self.assertEqual(str(IB16("6667f2a4").inst), "REPNZ MOVS BYTE [ES:EDI], [DS:ESI]")
		# 32 bits
		self.assertEqual(str(IB32("a4").inst), "MOVSB")
		self.assertEqual(str(IB32("66a5").inst), "MOVSW")
		self.assertEqual(str(IB32("a5").inst), "MOVSD")
		self.assertEqual(str(IB32("f3a5").inst), "REP MOVSD")
		self.assertEqual(str(IB32("66f3a5").inst), "REP MOVSW")
		self.assertEqual(str(IB32("f366a5").inst), "REP MOVSW")
		self.assertEqual(str(IB32("f3a5").inst), "REP MOVSD")
		self.assertEqual(str(IB32("f2a5").inst), "REPNZ MOVSD")
		self.assertEqual(str(IB32("65a5").inst), "MOVS DWORD [ES:EDI], [GS:ESI]")
		self.assertEqual(str(IB32("f365a5").inst), "REP MOVS DWORD [ES:EDI], [GS:ESI]")
		self.assertEqual(str(IB32("f36567a5").inst), "REP MOVS DWORD [ES:DI], [GS:SI]")
		self.assertEqual(str(IB32("f3656766a5").inst), "REP MOVS WORD [ES:DI], [GS:SI]")
		self.assertEqual(str(IB32("6667f365a5").inst), "REP MOVS WORD [ES:DI], [GS:SI]")
		self.assertEqual(str(IB32("6667f3a4").inst), "REP MOVS BYTE [ES:DI], [DS:SI]")
		self.assertEqual(str(IB32("6667f2a4").inst), "REPNZ MOVS BYTE [ES:DI], [DS:SI]")
		# 64 bits
		self.assertEqual(str(IB64("a4").inst), "MOVSB")
		self.assertEqual(str(IB64("66a5").inst), "MOVSW")
		self.assertEqual(str(IB64("a5").inst), "MOVSD")
		self.assertEqual(str(IB64("48a5").inst), "MOVSQ")
		self.assertEqual(str(IB64("4fa5").inst), "MOVSQ") # Set all REX bits, still MOVSQ.
		self.assertEqual(str(IB64("f3a5").inst), "REP MOVSD")
		self.assertEqual(str(IB64("f348a5").inst), "REP MOVSQ")
		self.assertEqual(str(IB64("f248a5").inst), "REPNZ MOVSQ")
		self.assertEqual(str(IB64("66f3a5").inst), "REP MOVSW")
		self.assertEqual(str(IB64("f366a5").inst), "REP MOVSW")
		self.assertEqual(str(IB64("f3a5").inst), "REP MOVSD")
		self.assertEqual(str(IB64("65a5").inst), "MOVS DWORD [RDI], [GS:RSI]")
		self.assertEqual(str(IB64("6548a5").inst), "MOVS QWORD [RDI], [GS:RSI]")
		self.assertEqual(str(IB64("f365a5").inst), "REP MOVS DWORD [RDI], [GS:RSI]")
		self.assertEqual(str(IB64("f367a5").inst), "REP MOVS DWORD [EDI], [ESI]")
		self.assertEqual(str(IB64("f3656766a5").inst), "REP MOVS WORD [EDI], [GS:ESI]")
		self.assertEqual(str(IB64("6667f365a5").inst), "REP MOVS WORD [EDI], [GS:ESI]")
		self.assertEqual(str(IB64("6667f36548a5").inst), "REP MOVS QWORD [EDI], [GS:ESI]")
		self.assertEqual(str(IB64("6667f3a4").inst), "REP MOVS BYTE [EDI], [ESI]")
	def test_cmps(self):
		""" CMPS instruction is treated specially with certain prefixes, check all such cases. """
		# 16 bits
		self.assertEqual(str(IB16("a6").inst), "CMPSB")
		self.assertEqual(str(IB16("66a7").inst), "CMPSD")
		self.assertEqual(str(IB16("a7").inst), "CMPSW")
		self.assertEqual(str(IB16("f3a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB16("66f3a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB16("f366a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB16("f3a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB16("65a7").inst), "CMPS WORD [GS:SI], [ES:DI]")
		self.assertEqual(str(IB16("f365a7").inst), "REPZ CMPS WORD [GS:SI], [ES:DI]")
		self.assertEqual(str(IB16("f36567a7").inst), "REPZ CMPS WORD [GS:ESI], [ES:EDI]")
		self.assertEqual(str(IB16("f3656766a7").inst), "REPZ CMPS DWORD [GS:ESI], [ES:EDI]")
		self.assertEqual(str(IB16("6667f365a7").inst), "REPZ CMPS DWORD [GS:ESI], [ES:EDI]")
		self.assertEqual(str(IB16("6667f3a6").inst), "REPZ CMPS BYTE [DS:ESI], [ES:EDI]")
		self.assertEqual(str(IB16("6667f2a6").inst), "REPNZ CMPS BYTE [DS:ESI], [ES:EDI]")
		# 32 bits
		self.assertEqual(str(IB32("a6").inst), "CMPSB")
		self.assertEqual(str(IB32("66a7").inst), "CMPSW")
		self.assertEqual(str(IB32("a7").inst), "CMPSD")
		self.assertEqual(str(IB32("f3a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB32("66f3a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB32("f366a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB32("f3a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB32("f2a7").inst), "REPNZ CMPSD")
		self.assertEqual(str(IB32("65a7").inst), "CMPS DWORD [GS:ESI], [ES:EDI]")
		self.assertEqual(str(IB32("f365a7").inst), "REPZ CMPS DWORD [GS:ESI], [ES:EDI]")
		self.assertEqual(str(IB32("f36567a7").inst), "REPZ CMPS DWORD [GS:SI], [ES:DI]")
		self.assertEqual(str(IB32("f3656766a7").inst), "REPZ CMPS WORD [GS:SI], [ES:DI]")
		self.assertEqual(str(IB32("6667f365a7").inst), "REPZ CMPS WORD [GS:SI], [ES:DI]")
		self.assertEqual(str(IB32("6667f3a6").inst), "REPZ CMPS BYTE [DS:SI], [ES:DI]")
		self.assertEqual(str(IB32("6667f2a6").inst), "REPNZ CMPS BYTE [DS:SI], [ES:DI]")
		# 64 bits
		self.assertEqual(str(IB64("a6").inst), "CMPSB")
		self.assertEqual(str(IB64("66a7").inst), "CMPSW")
		self.assertEqual(str(IB64("a7").inst), "CMPSD")
		self.assertEqual(str(IB64("48a7").inst), "CMPSQ")
		self.assertEqual(str(IB64("4fa7").inst), "CMPSQ") # Set all REX bits, still CMPSQ.
		self.assertEqual(str(IB64("f3a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB64("f348a7").inst), "REPZ CMPSQ")
		self.assertEqual(str(IB64("f248a7").inst), "REPNZ CMPSQ")
		self.assertEqual(str(IB64("66f3a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB64("f366a7").inst), "REPZ CMPSW")
		self.assertEqual(str(IB64("f3a7").inst), "REPZ CMPSD")
		self.assertEqual(str(IB64("65a7").inst), "CMPS DWORD [GS:RSI], [RDI]")
		self.assertEqual(str(IB64("6548a7").inst), "CMPS QWORD [GS:RSI], [RDI]")
		self.assertEqual(str(IB64("f365a7").inst), "REPZ CMPS DWORD [GS:RSI], [RDI]")
		self.assertEqual(str(IB64("f367a7").inst), "REPZ CMPS DWORD [ESI], [EDI]")
		self.assertEqual(str(IB64("f3656766a7").inst), "REPZ CMPS WORD [GS:ESI], [EDI]")
		self.assertEqual(str(IB64("6667f365a7").inst), "REPZ CMPS WORD [GS:ESI], [EDI]")
		self.assertEqual(str(IB64("6667f36548a7").inst), "REPZ CMPS QWORD [GS:ESI], [EDI]")
		self.assertEqual(str(IB64("6667f3a6").inst), "REPZ CMPS BYTE [ESI], [EDI]")
	def test_segment_override(self):
		self.assertEqual(I32("mov eax, [cs:eax]").inst.segment, Regs.CS)
		self.assertEqual(I32("mov eax, [ds:eax]").inst.segment, Regs.DS)
		self.assertEqual(I32("mov eax, [es:eax]").inst.segment, Regs.ES)
		self.assertEqual(I32("mov eax, [ss:eax]").inst.segment, Regs.SS)
		self.assertEqual(I32("mov eax, [fs:eax]").inst.segment, Regs.FS)
		self.assertEqual(I32("mov eax, [gs:eax]").inst.segment, Regs.GS)
	def test_unused_normal(self):
		self.assertEqual(IB64("4090").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("6790").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("6690").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("f290").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("f090").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("f3c3").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("64c3").inst.unusedPrefixesMask, 1)
	def test_unused_doubles(self):
		self.assertEqual(IB64("404090").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("676790").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("666690").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("f2f290").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("f0f090").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("f3f3c3").inst.unusedPrefixesMask, 3)
		self.assertEqual(IB64("642ec3").inst.unusedPrefixesMask, 3)
	def test_unused_sequences(self):
		self.assertEqual(len(IB64("66"*15).insts), 15)
		r = int(random.random() * 14)
		self.assertEqual(IB64("66"*r + "90").inst.unusedPrefixesMask, (1 << r) - 1)
	def test_rexw_66(self):
		self.assertEqual(IB64("6648ffc0").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("6640ffc0").inst.unusedPrefixesMask, 2)
		self.assertEqual(IB64("48660f10c0").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("664f0f10c0").inst.unusedPrefixesMask, 0)
	def test_last_segment(self):
		""" Only last segment is used as a prefix.
		Check tricky 64 bits too for default overrides. """
		self.assertEqual(IB32("2e260000").inst.segment, Regs.ES)
		self.assertEqual(IB32("2e260000").inst.unusedPrefixesMask, 1)
		self.assertEqual(IB64("2e650000").inst.segment, Regs.GS)
		self.assertEqual(IB64("652e0000").inst.segment, REG_NONE)
		self.assertEqual(IB64("652e0000").inst.unusedPrefixesMask, 3)

class TestInvalid(unittest.TestCase):
	def align(self):
		for i in range(15):
			IB32("90")
	def test_filter_mem(self):
		#cmpxchg8b eax
		IB32("0fc7c8")
		self.align()
	def test_drop_prefixes(self):
		# Drop prefixes when we encountered an instruction that couldn't be decoded.
		IB32("666764ffff")
		self.align()
	def test_zzz_must_be_last_drop_prefixes(self):
		# Drop prefixes when the last byte in stream is a prefix.
		IB32("66")
	def test_CR4_regression(self):
		# Regression test to validate CR4 isn't used as invalid default segment (-1 maps to CR4) in 64 bits.
		self.assertEqual(str(IB64("f20f104c1860").inst), "MOVSD XMM1, [RAX+RBX+0x60]")
		self.assertEqual(str(IB64("4883241e00").inst), "AND QWORD [RSI+RBX], 0x0")
	def test_undefined_byte00(self):
		# This is a regression test for the decomposer wrapper.
		a = ""
		insts = IB32("c300").insts
		for i in insts:
			a += str(i)
		insts = IB32("33c0" *  2000 + "90", 0, 0x4000).insts
		self.assertEqual(insts[-1].mnemonic, "NOP")
		self.assertEqual(insts[-1].instructionBytes, b"\x90")
		self.assertEqual(insts[-1].address, 0x4000 + 2000 * 2)
		self.assertEqual(insts[1000].mnemonic, "XOR")
		self.assertEqual(insts[1000].instructionBytes, b"\x33\xc0")
		self.assertEqual(insts[1000].address, 0x4000 + 1000 * 2)
	def test_prefix_regression(self):
		# We had a temporary code with a prefix length bug that wouldn't return an instruction.
		# So make sure we get an instruction where stream ends with last code byte.
		self.assertEqual(IB32("66af").insts[0].mnemonic, "SCAS")

class TestFeatures(unittest.TestCase):
	def test_addr16(self):
		#I16("mov [-4], bx", 0, DF_MAXIMUM_ADDR16).check_disp(0, 0xfffc, 16, 16)
		pass
	def test_add32(self):
		pass
	def test_fc(self):
		pairs = [
			(["INT 5", "db 0xf1", "INT 3", "INTO", "UD2"], distorm3.FlowControl.INT),
			(["CALL 0x50", "CALL FAR [ebx]"], distorm3.FlowControl.CALL),
			(["RET", "IRET", "RETF"], distorm3.FlowControl.RET),
			(["HLT"], distorm3.FlowControl.HLT),
			(["SYSCALL", "SYSENTER", "SYSRET", "SYSEXIT"], distorm3.FlowControl.SYS),
			(["JMP 0x50", "JMP FAR [ebx]"], distorm3.FlowControl.UNC_BRANCH),
			(["JCXZ 0x50", "JO 0x50", "JNO 0x50", "JB 0x50", "JAE 0x50",
			"JZ 0x50", "JNZ 0x50", "JBE 0x50", "JA 0x50", "JS 0x50",
			"JNS 0x50", "JP 0x50", "JNP 0x50", "JL 0x50", "JGE 0x50",
			"JLE 0x50", "JG 0x50", "LOOP 0x50", "LOOPZ 0x50", "LOOPNZ 0x50"], distorm3.FlowControl.CND_BRANCH)
		]
		for i in pairs:
			for j in i[0]:
				a = I32(j + "\nnop", distorm3.DF_STOP_ON_FLOW_CONTROL)
				self.assertEqual(len(a.insts), 1)
				self.assertEqual(a.inst.meta & 0xf, i[1])
				a = I32("push eax\nnop\n" + j, distorm3.DF_RETURN_FC_ONLY)
				self.assertEqual(len(a.insts), 1)
				a = I32("nop\nxor eax, eax\n" + j + "\ninc eax", distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)
				self.assertEqual(len(a.insts), 1)
	def test_filter(self):
		a = IB32("33c0907e00" * 5, distorm3.DF_RETURN_FC_ONLY).insts
		self.assertEqual(len(a), 5)
		self.assertEqual(a[0].mnemonic[0], "J")
		self.assertEqual(a[0].address, 3)
		self.assertEqual(a[1].address, 8)
		self.assertEqual(a[2].address, 13)
		self.assertEqual(a[3].address, 18)
		self.assertEqual(a[4].address, 23)
	def test_stop_on_privileged(self):
		a = I32("nop\niret\nret", distorm3.DF_STOP_ON_PRIVILEGED)
		self.assertEqual(len(a.insts), 2)
		a = I64("mov eax, ebx\nnop\ncli\nnop", distorm3.DF_STOP_ON_PRIVILEGED)
		self.assertEqual(len(a.insts), 3)
	def test_step_byte(self):
		a = IB32("90b833c3eb48", distorm3.DF_SINGLE_BYTE_STEP).insts
		self.assertEqual(a[0].address, 0)
		self.assertEqual(a[0].mnemonic, "NOP")
		self.assertEqual(a[0].size, 1)
		self.assertEqual(a[1].address, 1)
		self.assertEqual(a[1].mnemonic, "MOV")
		self.assertEqual(a[1].size, 5)
		self.assertEqual(a[2].address, 2)
		self.assertEqual(a[2].mnemonic, "XOR")
		self.assertEqual(a[2].size, 2)
		self.assertEqual(a[3].address, 3)
		self.assertEqual(a[3].mnemonic, "RET")
		self.assertEqual(a[3].size, 1)
		self.assertEqual(a[4].address, 4)
		self.assertEqual(a[4].mnemonic, "JMP")
		self.assertEqual(a[4].size, 2)
		self.assertEqual(a[5].address, 5)
		self.assertEqual(a[5].mnemonic, "DEC")
		self.assertEqual(a[5].size, 1)
	def test_eflags_on(self):
		a = IB32("33c04890", distorm3.DF_FILL_EFLAGS).insts
		# XOR
		self.assertEqual(a[0].modifiedFlags, distorm3.D_SF | distorm3.D_ZF | distorm3.D_PF)
		self.assertEqual(a[0].testedFlags, 0)
		self.assertEqual(a[0].undefinedFlags, distorm3.D_AF)
		# INC
		self.assertEqual(a[1].modifiedFlags, distorm3.D_OF | distorm3.D_SF | distorm3.D_ZF | distorm3.D_AF | distorm3.D_PF)
		self.assertEqual(a[1].testedFlags, 0)
		self.assertEqual(a[1].undefinedFlags, 0)
		# NOP
		self.assertEqual(a[2].modifiedFlags, 0)
		self.assertEqual(a[2].testedFlags, 0)
		self.assertEqual(a[2].undefinedFlags, 0)
	def test_eflags_off(self):
		a = IB32("33c04890").insts
		# XOR
		self.assertEqual(a[0].modifiedFlags, 0)
		self.assertEqual(a[0].testedFlags, 0)
		self.assertEqual(a[0].undefinedFlags, 0)
		# INC
		self.assertEqual(a[1].modifiedFlags, 0)
		self.assertEqual(a[1].testedFlags, 0)
		self.assertEqual(a[1].undefinedFlags, 0)
		# NOP
		self.assertEqual(a[2].modifiedFlags, 0)
		self.assertEqual(a[2].testedFlags, 0)
		self.assertEqual(a[2].undefinedFlags, 0)
	def test_stop_undecodable(self):
		self.assertEqual(len(IB16("909033c0ffff90", distorm3.DF_STOP_ON_UNDECODEABLE).insts), 4)
		self.assertEqual(len(IB32("909033c090ffff90", distorm3.DF_STOP_ON_UNDECODEABLE).insts), 5)
		self.assertEqual(len(IB64("909033c09090ffff9090", distorm3.DF_STOP_ON_UNDECODEABLE).insts), 6)

class TestAPI(unittest.TestCase):
	def direct_decompose(self, code, codeOffset, dt, features, maxInstructions):
		codeLen         = len(code)
		code_buf        = ctypes.create_string_buffer(code)
		p_code          = ctypes.byref(code_buf)
		result          = (distorm3._DInst * maxInstructions)()
		p_result        = ctypes.byref(result)
		usedInstructionsCount = ctypes.c_uint(0)
		codeInfo = distorm3._CodeInfo(distorm3._OffsetType(codeOffset), distorm3._OffsetType(0), distorm3._OffsetType(0), ctypes.cast(p_code, ctypes.c_char_p), codeLen, dt, features)
		status = distorm3.internal_decompose(ctypes.byref(codeInfo), ctypes.byref(result), maxInstructions, ctypes.byref(usedInstructionsCount))
		return (status, usedInstructionsCount.value, result)
	def test_out_buf(self):
		s, count, results = self.direct_decompose(b"\x90\x90", 0, distorm3.Decode32Bits, 0, 0)
		self.assertEqual(s, distorm3.DECRES_INPUTERR)
		s, count, results = self.direct_decompose(b"\x90\x90", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 1)
		s, count, results = self.direct_decompose(b"\x90\x90", 0, distorm3.Decode32Bits, 0, 2)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 2)
	def test_0_len(self):
		s, count, results = self.direct_decompose(b"", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		s, count, results = self.direct_decompose(b"", 0x1234, distorm3.Decode64Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
	def test_bad_features(self):
		s, count, results = self.direct_decompose(b"\x90", 0, distorm3.Decode32Bits, distorm3.DF_MAXIMUM_ADDR16 | distorm3.DF_MAXIMUM_ADDR32, 1)
		self.assertEqual(s, distorm3.DECRES_INPUTERR)
	def test_bad_decoding_type(self):
		s, count, results = self.direct_decompose(b"\x90", 0, -1, 0, 1)
		self.assertEqual(s, distorm3.DECRES_INPUTERR)
		s, count, results = self.direct_decompose(b"\x90", 0, 3, 0, 1)
		self.assertEqual(s, distorm3.DECRES_INPUTERR)
	def test_single_out_buf(self):
		s, count, results = self.direct_decompose(b"\x66\x90", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 1)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "NOP")
		s, count, results = self.direct_decompose(b"\x66\x67", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 1)
		self.assertEqual(results[0].imm.byte, 0x66)
		s, count, results = self.direct_decompose(b"\x66\x67", 0, distorm3.Decode32Bits, 0, 2)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 2)
		self.assertEqual(results[0].imm.byte, 0x66)
		self.assertEqual(results[1].imm.byte, 0x67)
		s, count, results = self.direct_decompose(b"\x66\x67", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 1)
	def test_drop_skip(self):
		s, count, results = self.direct_decompose(b"\x05\x00\x01", 0, distorm3.Decode32Bits, 0, 1) # Skips 05, then returns add [ecx], al
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 1)
		s, count, results = self.direct_decompose(b"\x05\x00\x01", 0, distorm3.Decode32Bits, 0, 2)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 2)
		s, count, results = self.direct_decompose(b"\xc4\x01", 0, distorm3.Decode32Bits, 0, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 1)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "LES")
		s, count, results = self.direct_decompose(b"\xc5\xc5", 0, distorm3.Decode32Bits, 0, 2)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 2)
		self.assertEqual(results[0].imm.byte, 0xc5)
		self.assertEqual(results[1].imm.byte, 0xc5)
		s, count, results = self.direct_decompose(b"\xc5\xc5\xc5", 0, distorm3.Decode32Bits, 0, 3)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 3)
		self.assertEqual(results[0].imm.byte, 0xc5)
		self.assertEqual(results[1].imm.byte, 0xc5)
		self.assertEqual(results[2].imm.byte, 0xc5)
	def test_fc(self):
		s, count, results = self.direct_decompose(b"\x90", 0, distorm3.Decode32Bits, distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 0)
		s, count, results = self.direct_decompose(b"\x90\x75\x00", 0, distorm3.Decode32Bits, distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 1)
	def test_single_step(self):
		s, count, results = self.direct_decompose(b"\x33\xff\xc0", 0, distorm3.Decode32Bits, distorm3.DF_SINGLE_BYTE_STEP, 1)
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 1)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "XOR")
		s, count, results = self.direct_decompose(b"\x33\xff\xc0", 0, distorm3.Decode32Bits, distorm3.DF_SINGLE_BYTE_STEP, 2)
		self.assertEqual(s, distorm3.DECRES_MEMORYERR)
		self.assertEqual(count, 2)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "XOR")
		self.assertEqual(Mnemonics.get(results[1].opcode, ""), "INC")
		s, count, results = self.direct_decompose(b"\x33\xff\xc0", 0, distorm3.Decode32Bits, distorm3.DF_SINGLE_BYTE_STEP, 3)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 3)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "XOR")
		self.assertEqual(Mnemonics.get(results[1].opcode, ""), "INC")
		self.assertEqual(results[2].imm.byte, 0xc0)
	def test_fc_and_single_step(self):
		s, count, results = self.direct_decompose(b"\x33\xc3", 0, distorm3.Decode32Bits, distorm3.DF_SINGLE_BYTE_STEP | distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 1)
		self.assertEqual(Mnemonics.get(results[0].opcode, ""), "RET")
	def test_fc_dropped(self):
		s, count, results = self.direct_decompose(b"\x33\xc3", 0, distorm3.Decode64Bits, distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 0)
		s, count, results = self.direct_decompose(b"\x66\x67\x90\xc3", 0, distorm3.Decode64Bits, distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 1)
		s, count, results = self.direct_decompose(b"\x66\x67", 0, distorm3.Decode64Bits, distorm3.DF_RETURN_FC_ONLY, 1)
		self.assertEqual(s, distorm3.DECRES_SUCCESS)
		self.assertEqual(count, 0)

def GetNewSuite(className):
	suite = unittest.TestSuite()
	suite.addTest(unittest.makeSuite(className))
	return suite

def initfiles():
	for i in ["bin16", "bin32", "bin64"]:
		fbin.append(open("build\\linux\\"+i, "wb"))

if __name__ == "__main__":
	random.seed()
	#initfiles() # Used to emit the bytes of the tests - useful for code coverage input.
	suite = unittest.TestSuite()
	suite.addTest(GetNewSuite(TestMode16))
	suite.addTest(GetNewSuite(TestMode32))
	suite.addTest(GetNewSuite(TestMode64))
	suite.addTest(GetNewSuite(TestInstTable))
	suite.addTest(GetNewSuite(TestAVXOperands))
	suite.addTest(GetNewSuite(TestMisc))
	suite.addTest(GetNewSuite(TestMisc2))
	suite.addTest(GetNewSuite(TestPrefixes))
	suite.addTest(GetNewSuite(TestInvalid))
	suite.addTest(GetNewSuite(TestFeatures))
	suite.addTest(GetNewSuite(TestAPI))
	result = unittest.TextTestRunner(verbosity=1).run(suite)
	if result.wasSuccessful():
		exit(0)
	else:
		exit(1)
