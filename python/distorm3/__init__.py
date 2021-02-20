# :[diStorm3}: Python binding
# Based on diStorm64 Python binding by Mario Vilas
# Initial support for decompose API added by Roee Shenberg
# Licensed under BSD in 2016.
#
# Compatible with Python2.x and 3.x.
#

info = (
    "diStorm3 by Gil Dabah, https://github.com/gdabah/distorm/\n"
    "Based on diStorm64 Python binding by Mario Vilas, http://breakingcode.wordpress.com/\n"
)

__revision__ = "$Id: distorm.py 186 2010-05-01 14:20:41Z gdabah $"

__all__ = [
    'Decode',
    'DecodeGenerator',
    'Decompose',
    'DecomposeGenerator',
    'Decode16Bits',
    'Decode32Bits',
    'Decode64Bits',
    'Mnemonics',
    'Registers',
    'RegisterMasks'
]

from ctypes import *
import os
import sys
from ._generated import Registers, Mnemonics, RegisterMasks

if sys.version_info[0] >= 3:
    xrange = range

#==============================================================================
# Load the diStorm DLL

def _load_distorm():
    if sys.version_info[0] == 3:
        try:
            import _distorm3
            return cdll.LoadLibrary(_distorm3.__spec__.origin)
        except ImportError:
            pass

    dll_ext = ('.dll' if sys.platform == 'win32' else '.so')
    libnames = ['_distorm3' + dll_ext, '_distorm3.pyd']
    for dir in sys.path:
        for name in libnames:
            _distorm_file = os.path.join(dir, name)
            if os.path.isfile(_distorm_file):
                return cdll.LoadLibrary(_distorm_file)
    raise ImportError("Error loading the diStorm dynamic library (or cannot load library into process).")

_distorm = _load_distorm()

# Get the decode C function (try 64 bits version first, only then 32 bits).
SUPPORT_64BIT_OFFSET = False
try:
    internal_decode = _distorm.distorm_decode64
    internal_decompose = _distorm.distorm_decompose64
    internal_format = _distorm.distorm_format64
    SUPPORT_64BIT_OFFSET = True
except AttributeError:
    internal_decode = _distorm.distorm_decode32
    internal_decompose = _distorm.distorm_decompose32
    internal_format = _distorm.distorm_format32

#==============================================================================
# diStorm C interface

MAX_TEXT_SIZE       = 48 # See distorm.h for this value.
MAX_INSTRUCTIONS    = 1000

DECRES_NONE         = 0
DECRES_SUCCESS      = 1
DECRES_MEMORYERR    = 2
DECRES_INPUTERR     = 3

if SUPPORT_64BIT_OFFSET:
    _OffsetType = c_ulonglong
else:
    _OffsetType = c_uint

class _WString (Structure):
    _fields_ = [
        ('length',  c_uint),
        ('p',       c_char * MAX_TEXT_SIZE),
    ]

class _CodeInfo (Structure):
    _fields_ = [
        ('codeOffset',  _OffsetType),
        ('addrMask',    _OffsetType),
        ('nextOffset',  _OffsetType),
        ('code',        c_char_p),
        ('codeLen',     c_int),
        ('dt',          c_byte),
        ('features',    c_uint),
        ]

class _DecodedInst (Structure):
    _fields_ = [
        ('offset',          _OffsetType),
        ('size',            c_uint),
        ('mnemonic',        _WString),
        ('operands',        _WString),
        ('instructionHex',  _WString)
    ]

# _OperandType enum
_OperandType = c_ubyte

O_NONE = 0
O_REG  = 1
O_IMM  = 2
O_IMM1 = 3
O_IMM2 = 4
O_DISP = 5
O_SMEM = 6
O_MEM  = 7
O_PC   = 8
O_PTR  = 9

class _Operand (Structure):
    _fields_ = [
        ('type',  c_ubyte), # of type _OperandType
        ('index', c_ubyte),
        ('size',  c_uint16),
    ]

class _ex (Structure):
    _fields_ = [
        ('i1', c_uint32),
        ('i2', c_uint32),
    ]
class _ptr (Structure):
    _fields_ = [
        ('seg', c_uint16),
        ('off', c_uint32),
    ]

class _Value (Union):
    _fields_ = [
        ('sbyte', c_byte),
        ('byte', c_ubyte),
        ('sword', c_int16),
        ('word', c_uint16),
        ('sdword', c_int32),
        ('dword', c_uint32),
        ('sqword', c_int64),
        ('qword', c_uint64),
        ('addr', _OffsetType),
        ('ptr', _ptr),
        ('ex', _ex),
        ]

class _DInst (Structure):
    _fields_ = [
        ('imm', _Value),
        ('disp', c_uint64),    # displacement. size is according to dispSize
        ('addr',  _OffsetType),
        ('flags',  c_uint16), # -1 if invalid. See C headers for more info
        ('unusedPrefixesMask', c_uint16),
        ('usedRegistersMask', c_uint32), # used registers mask
        ('opcode', c_uint16),  # look up in opcode table
        ('ops', _Operand*4),
        ('opsNo', c_ubyte), # number of valid ops
        ('size', c_ubyte),
        ('segment', c_ubyte), # -1 if unused. See C headers for more info
        ('base', c_ubyte),    # base register for indirections
        ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
        ('dispSize', c_ubyte),
        ('meta', c_uint16), # meta flags - instruction set class, etc. See C headers again...
        ('modifiedFlagsMask', c_uint16), # CPU modified (output) flags by instruction only set with DF_FILL_EFLAGS
        ('testedFlagsMask', c_uint16), # CPU tested (input) flags by instruction only set with DF_FILL_EFLAGS
        ('undefinedFlagsMask', c_uint16) # CPU undefined flags by instruction only set with DF_FILL_EFLAGS
        ]

#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType)

# Special case
R_NONE = 0xFF # -1 in uint8

FLAGS = [
# The instruction locks memory access.
"FLAG_LOCK",
# The instruction is prefixed with a REPNZ.
"FLAG_REPNZ",
# The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
"FLAG_REP",
# Indicates there is a hint taken for Jcc instructions only.
"FLAG_HINT_TAKEN",
# Indicates there is a hint non-taken for Jcc instructions only.
"FLAG_HINT_NOT_TAKEN",
# The Imm value is signed extended.
"FLAG_IMM_SIGNED",
# The destination operand is writable.
"FLAG_DST_WR",
# The instruction uses the RIP-relative indirection.
"FLAG_RIP_RELATIVE"
]

# CPU flags that instructions modify, test or undefine (are EFLAGS compatible!).
D_CF = 1     # Carry #
D_PF = 4     # Parity #
D_AF = 0x10  # Auxiliary #
D_ZF = 0x40  # Zero #
D_SF = 0x80  # Sign #
D_IF = 0x200 # Interrupt #
D_DF = 0x400 # Direction #
D_OF = 0x800 # Overflow #

# Instruction could not be disassembled. Special-case handling
FLAG_NOT_DECODABLE = 0xFFFF # -1 in uint16
# Some features
DF_NONE = 0
DF_MAXIMUM_ADDR16 = 1
DF_MAXIMUM_ADDR32 = 2
DF_RETURN_FC_ONLY = 4
# Flow control flags
DF_STOP_ON_CALL = 0x8
DF_STOP_ON_RET  = 0x10
DF_STOP_ON_SYS  = 0x20
DF_STOP_ON_UNC_BRANCH  = 0x40
DF_STOP_ON_CND_BRANCH  = 0x80
DF_STOP_ON_INT  = 0x100
DF_STOP_ON_CMOV  = 0x200
DF_STOP_ON_HLT  = 0x400
DF_STOP_ON_PRIVILEGED = 0x800
DF_STOP_ON_UNDECODEABLE = 0x1000
DF_SINGLE_BYTE_STEP = 0x2000
DF_FILL_EFLAGS = 0x4000
DF_USE_ADDR_MASK = 0x8000

DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | \
    DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV | \
    DF_STOP_ON_HLT)

def DecodeGenerator(codeOffset, code, dt):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  generator of tuple( long, int, str, str )
    @return: Generator of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """

    if not code:
        return

    if not codeOffset:
        codeOffset = 0

    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError("Invalid decode type value: %r" % (dt,))

    codeLen         = len(code)
    code_buf        = create_string_buffer(code)
    p_code          = byref(code_buf)
    result          = (_DecodedInst * MAX_INSTRUCTIONS)()
    p_result        = byref(result)
    instruction_off = 0

    # Support cross Python compatibility
    toUnicode = lambda s: s
    spaceCh = b" "
    if sys.version_info[0] >= 3:
        if sys.version_info[1] > 0:
            toUnicode = lambda s: s.decode()
        else:
            spaceCh = " "

    while codeLen > 0:

        usedInstructionsCount = c_uint(0)
        status = internal_decode(_OffsetType(codeOffset), p_code, codeLen, dt, p_result, MAX_INSTRUCTIONS, byref(usedInstructionsCount))

        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        for index in xrange(used):
            di   = result[index]
            asm  = di.mnemonic.p
            if len(di.operands.p):
                asm += spaceCh + di.operands.p
            pydi = (di.offset, di.size, toUnicode(asm), toUnicode(di.instructionHex.p))
            instruction_off += di.size
            yield pydi

        di         = result[used - 1]
        delta      = di.offset - codeOffset + result[used - 1].size
        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, instruction_off)
        codeLen    = codeLen - delta

def Decode(offset, code, type = Decode32Bits):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  list of tuple( long, int, str, str )
    @return: List of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """
    return list(DecodeGenerator(offset, code, type))

OPERAND_NONE = ""
OPERAND_IMMEDIATE = "Immediate"
OPERAND_REGISTER = "Register"

# the operand is a memory address
OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress" # The address calculated is absolute
OPERAND_MEMORY = "AbsoluteMemory" # The address calculated uses registers expression
OPERAND_FAR_MEMORY = "FarMemory" # like absolute but with selector/segment specified too

InstructionSetClasses = [
"ISC_UNKNOWN",
# Indicates the instruction belongs to the General Integer set.
"ISC_INTEGER",
# Indicates the instruction belongs to the 387 FPU set.
"ISC_FPU",
# Indicates the instruction belongs to the P6 set.
"ISC_P6",
# Indicates the instruction belongs to the MMX set.
"ISC_MMX",
# Indicates the instruction belongs to the SSE set.
"ISC_SSE",
# Indicates the instruction belongs to the SSE2 set.
"ISC_SSE2",
# Indicates the instruction belongs to the SSE3 set.
"ISC_SSE3",
# Indicates the instruction belongs to the SSSE3 set.
"ISC_SSSE3",
# Indicates the instruction belongs to the SSE4.1 set.
"ISC_SSE4_1",
# Indicates the instruction belongs to the SSE4.2 set.
"ISC_SSE4_2",
# Indicates the instruction belongs to the AMD's SSE4.A set.
"ISC_SSE4_A",
# Indicates the instruction belongs to the 3DNow! set.
"ISC_3DNOW",
# Indicates the instruction belongs to the 3DNow! Extensions set.
"ISC_3DNOWEXT",
# Indicates the instruction belongs to the VMX (Intel) set.
"ISC_VMX",
# Indicates the instruction belongs to the SVM (AMD) set.
"ISC_SVM",
# Indicates the instruction belongs to the AVX (Intel) set.
"ISC_AVX",
# Indicates the instruction belongs to the FMA (Intel) set.
"ISC_FMA",
# Indicates the instruction belongs to the AES/AVX (Intel) set.
"ISC_AES",
# Indicates the instruction belongs to the CLMUL (Intel) set.
"ISC_CLMUL",
]

FlowControlFlags = [
# Indicates the instruction is not a flow-control instruction.
"FC_NONE",
# Indicates the instruction is one of: CALL, CALL FAR.
"FC_CALL",
# Indicates the instruction is one of: RET, IRET, RETF.
"FC_RET",
# Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
"FC_SYS",
# Indicates the instruction is one of: JMP, JMP FAR.
"FC_UNC_BRANCH",
# Indicates the instruction is one of:
# JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
"FC_CND_BRANCH",
# Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
"FC_INT",
# Indicates the instruction is one of: CMOVxx.
"FC_CMOV",
# Indicates the instruction is HLT.
"FC_HLT",
]

# TODO: put FlowControlFlags together in one class with _repr_.
class FlowControl:
    """ The flow control instruction will be flagged in the lo byte of the 'meta' field in _InstInfo of diStorm.
    They are used to distinguish between flow control instructions (such as: ret, call, jmp, jz, etc) to normal ones. """
    (CALL,
    RET,
    SYS,
    UNC_BRANCH,
    CND_BRANCH,
    INT,
    CMOV,
    HLT) = range(1, 9)

def _getOpSize(flags):
    return ((flags >> 7) & 3)

def _getISC(metaflags):
    realvalue = ((metaflags >> 8) & 0x1f)
    try:
        return InstructionSetClasses[realvalue]
    except IndexError:
        print ("Bad ISC flags in meta member: {}".format(realvalue))
        raise

def _getFC(metaflags):
    realvalue = (metaflags & 0xf)
    try:
        return FlowControlFlags[realvalue]
    except IndexError:
        print ("Bad FlowControl flags in meta member: {}".format(realvalue))
        raise

def _getMnem(opcode):
    return Mnemonics.get(opcode, "UNDEFINED")

def _unsignedToSigned64(val):
    return int(val if val < 0x8000000000000000 else (val - 0x10000000000000000))

def _unsignedToSigned32(val):
    return int(val if val < 0x80000000 else (val - 0x10000000))

if SUPPORT_64BIT_OFFSET:
    _unsignedToSigned = _unsignedToSigned64
else:
    _unsignedToSigned = _unsignedToSigned32

class Operand (object):
    def __init__(self, type, *args):
        self.type = type
        self.index = None
        self.name = ""
        self.size = 0
        self.value = 0
        self.disp = 0
        self.dispSize = 0
        self.base = 0
        self.segment = 0
        if type == OPERAND_IMMEDIATE:
            self.value = int(args[0])
            self.size = args[1]
        elif type == OPERAND_REGISTER:
            self.index = args[0]
            self.size = args[1]
            self.name = Registers[self.index]
        elif type == OPERAND_MEMORY:
            self.base = args[0] if args[0] != R_NONE else None
            self.index = args[1]
            self.size = args[2]
            self.scale = args[3] if args[3] > 1 else 1
            self.disp = int(args[4])
            self.dispSize = args[5]
            self.segment = args[6]
        elif type == OPERAND_ABSOLUTE_ADDRESS:
            self.size = args[0]
            self.disp = int(args[1])
            self.dispSize = args[2]
            self.segment = args[3]
        elif type == OPERAND_FAR_MEMORY:
            self.size = args[2]
            self.seg = args[0]
            self.off = args[1]

    def _toText(self):
        if self.type == OPERAND_IMMEDIATE:
            if self.value >= 0:
                return "0x%x" % self.value
            else:
                return "-0x%x" % abs(self.value)
        elif self.type == OPERAND_REGISTER:
            return self.name
        elif self.type == OPERAND_ABSOLUTE_ADDRESS:
            return '[0x%x]' % self.disp
        elif self.type == OPERAND_FAR_MEMORY:
            return '%s:%s' % (hex(self.seg), hex(self.off))
        elif (self.type == OPERAND_MEMORY):
            result = "["
            if self.base != None:
                result += Registers[self.base] + "+"
            if self.index != None:
                result += Registers[self.index]
                if self.scale > 1:
                    result += "*%d" % self.scale
            if self.disp >= 0:
                result += "+0x%x" % self.disp
            else:
                result += "-0x%x" % abs(self.disp)
            return result + "]"
    def __str__(self):
        return self._toText()


class Instruction (object):
    def __init__(self, di, instructionBytes, dt):
        "Expects a filled _DInst structure, and the corresponding byte code of the whole instruction"
        #self.di = di
        flags = di.flags
        self.instructionBytes = instructionBytes
        self.opcode = di.opcode
        self.operands = []
        self.flags = []
        self.rawFlags = di.flags
        self.meta = 0
        self.privileged = False
        self.instructionClass = _getISC(0)
        self.flowControl = _getFC(0)
        self.address = di.addr
        self.size = di.size
        self.dt = dt
        self.valid = False
        if di.segment != R_NONE:
            self.segment = di.segment & 0x7f
            self.isSegmentDefault = (di.segment & 0x80) == 0x80
        else:
            self.segment = R_NONE
            self.isSegmentDefault = False
        self.unusedPrefixesMask = di.unusedPrefixesMask
        self.usedRegistersMask = di.usedRegistersMask

        # calculate register masks
        self.registers = []
        maskIndex = 1
        v = self.usedRegistersMask
        while (v):
            if (v & maskIndex):
                self.registers.append(RegisterMasks[maskIndex])
                v ^= maskIndex
            maskIndex <<= 1

        if flags == FLAG_NOT_DECODABLE:
            self.mnemonic = 'DB 0x%02x' % (di.imm.byte)
            self.flags = ['FLAG_NOT_DECODABLE']
            return

        self.valid = True
        self.mnemonic = _getMnem(self.opcode)

        # decompose the flags for a valid opcode
        for index, flag in enumerate(FLAGS):
            if (flags & (1 << index)) != 0:
                self.flags.append(flag)

        # read the operands
        for operand in di.ops:
            if operand.type != O_NONE:
                self.operands.append(self._extractOperand(di, operand))

        # decode the meta-flags
        metas = di.meta
        self.meta = di.meta
        self.privileged = (metas & 0x8000) == 0x8000
        self.instructionClass = _getISC(metas)
        self.flowControl = _getFC(metas)

        # copy eflags
        self.modifiedFlags = di.modifiedFlagsMask
        self.undefinedFlags = di.undefinedFlagsMask
        self.testedFlags = di.testedFlagsMask

    def _extractOperand(self, di, operand):
        # a single operand can be up to: reg1 + reg2*scale + constant
        if operand.type == O_IMM:
            if ("FLAG_IMM_SIGNED" in self.flags):
                # immediate is sign-extended, do your thing. it's already signed, just make it Python-signed.
                constant = _unsignedToSigned(di.imm.sqword)
            else:
                # immediate is zero-extended, though it's already aligned.
                constant = di.imm.qword
            return Operand(OPERAND_IMMEDIATE, constant, operand.size)
        elif operand.type == O_IMM1: # first operand for ENTER
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.i1, operand.size)
        elif operand.type == O_IMM2: # second operand for ENTER
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.i2, operand.size)
        elif operand.type == O_REG:
            return Operand(OPERAND_REGISTER, operand.index, operand.size)
        elif operand.type == O_MEM:
            return Operand(OPERAND_MEMORY, di.base, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize, self.segment)
        elif operand.type == O_SMEM:
            return Operand(OPERAND_MEMORY, None, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize, self.segment)
        elif operand.type == O_DISP:
            return Operand(OPERAND_ABSOLUTE_ADDRESS, operand.size, di.disp, di.dispSize, self.segment)
        elif operand.type == O_PC:
            return Operand(OPERAND_IMMEDIATE, _unsignedToSigned(di.imm.addr) + self.address + self.size, operand.size)
        elif operand.type == O_PTR:
            return Operand(OPERAND_FAR_MEMORY, di.imm.ptr.seg, di.imm.ptr.off, operand.size)
        else:
            raise ValueError("Unknown operand type encountered: %d!" % operand.type)

    def _toText(self):
        # use the decode which already returns the text formatted well (with prefixes, etc).
        return Decode(self.address, self.instructionBytes, self.dt)[0][2]

    def __str__(self):
        return self._toText()


def DecomposeGenerator(codeOffset, code, dt, features = 0):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str, in Py3 bytes
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @type  features: int
    @param features: A flow control stopping criterion, eg. DF_STOP_ON_CALL.
                     or other features, eg. DF_RETURN_FC_ONLY.

    @rtype:  generator of TODO
    @return: Generator of TODO

    @raise ValueError: Invalid arguments.
    """

    if not code:
        return

    if not codeOffset:
        codeOffset = 0

    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError("Invalid decode type value: %r" % (dt,))

    codeLen         = len(code)
    code_buf        = create_string_buffer(code)
    p_code          = byref(code_buf)
    result          = (_DInst * MAX_INSTRUCTIONS)()
    startCodeOffset = codeOffset

    while codeLen > 0:

        usedInstructionsCount = c_uint(0)
        codeInfo = _CodeInfo(_OffsetType(codeOffset), _OffsetType(0), _OffsetType(0), cast(p_code, c_char_p), codeLen, dt, features)
        status = internal_decompose(byref(codeInfo), byref(result), MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        for index in range(used):
            di = result[index]
            yield Instruction(di, code[di.addr - startCodeOffset : di.addr - startCodeOffset + di.size], dt)

        lastInst = result[used - 1]
        delta = lastInst.addr + lastInst.size - codeOffset
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, codeOffset - startCodeOffset)
        codeLen    = codeLen - delta

        if (features & (DF_STOP_ON_FLOW_CONTROL | DF_STOP_ON_PRIVILEGED | DF_STOP_ON_UNDECODEABLE)) != 0:
            break # User passed a stop flag.

def Decompose(offset, code, type = Decode32Bits, features = 0):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str, in Py3 bytes
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @type  features: int
    @param features: A flow control stopping criterion, eg. DF_STOP_ON_CALL.
                     or other features, eg. DF_RETURN_FC_ONLY.

    @rtype:  TODO
    @return: TODO
    @raise ValueError: Invalid arguments.
    """
    return list(DecomposeGenerator(offset, code, type, features))
