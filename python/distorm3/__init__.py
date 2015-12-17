# :[diStorm3}: Python binding
# Based on diStorm64 Python binding by Mario Vilas
# Initial support for decompose API added by Roee Shenberg
# Changed license to GPLv3.
#
# Compatible with Python2.6 and above.
#

info = (
    "diStorm3 by Gil Dabah, http://code.google.com/p/distorm/\n"
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
]

from ctypes import *
from os.path import split, join
from os import name as os_name
import sys

#==============================================================================
# Load the diStorm DLL

# Guess the DLL filename and load the library.
_distorm_path = split(__file__)[0]
if hasattr(sys, '_MEIPASS'):
    _distorm_path = sys._MEIPASS
potential_libs = ['libdistorm3.so', 'libdistorm3.dylib']
if os_name == 'nt':
    potential_libs = ['distorm3.dll', 'libdistorm3.dll']
lib_was_found = False
for i in potential_libs:
    try:
        _distorm_file = join(_distorm_path, i)
        _distorm = cdll.LoadLibrary(_distorm_file)
        lib_was_found = True
        break
    except OSError:
        pass

if lib_was_found == False:
    raise ImportError("Error loading the diStorm dynamic library (or cannot load library into process).")

# Get the decode C function (try 64 bits version first, only then 32 bits).
SUPPORT_64BIT_OFFSET = False
try:
    internal_decode = _distorm.distorm_decode64
    internal_decompose = _distorm.distorm_decompose64
    internal_format = _distorm.distorm_format64
    SUPPORT_64BIT_OFFSET = True
except AttributeError:
    try:
          internal_decode = _distorm.distorm_decode32
          internal_decompose = _distorm.distorm_decompose32
          internal_format = _distorm.distorm_format32
    except AttributeError:
        raise ImportError("Error loading distorm")

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
        ('codeOffset',	_OffsetType),
        ('nextOffset',  _OffsetType),
        ('code',        c_char_p),
        ('codeLen',     c_int),
        ('dt',          c_byte),
        ('features',    c_uint),
        ]

class _DecodedInst (Structure):
    _fields_ = [
        ('mnemonic',        _WString),
        ('operands',        _WString),
        ('instructionHex',  _WString),
        ('size',            c_uint),
        ('offset',          _OffsetType),
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
        ('usedRegistersMask', c_uint32), # used registers mask.
        ('opcode', c_uint16),  # look up in opcode table
        ('ops', _Operand*4),
        ('size', c_ubyte),
        ('segment', c_ubyte), # -1 if unused. See C headers for more info
        ('base', c_ubyte),    # base register for indirections
        ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
        ('dispSize', c_ubyte),
        ('meta', c_ubyte), # meta flags - instruction set class, etc. See C headers again...
        ('modifiedFlagsMask', c_uint16), # CPU modified (output) flags by instruction.
        ('testedFlagsMask', c_uint16), # CPU tested (input) flags by instruction.
        ('undefinedFlagsMask', c_uint16) # CPU undefined flags by instruction.
        ]

#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType)

Mnemonics = {0x669: "SLDT", 0x62: "POPA", 0x8f4: "UNPCKHPS", 0x115: "POPF", 0x11bf: "CMPLTSS",
0x865: "VMOVSD", 0x78f: "PFPNACC", 0xb1a: "VMOVMSKPD", 0x73d: "INVLPGA", 0x8fe: "UNPCKHPD",
0x270: "SYSEXIT", 0x7b8: "PFSUB", 0x120e: "CMPLTSD", 0x1a63: "VPMULHUW", 0x1d3b: "VPHSUBSW",
0x12b8: "VCMPNGEPS", 0x85d: "VMOVSS", 0x6f: "ARPL", 0x52a: "FICOMP", 0x162: "RETF",
0x44d: "FCHS", 0x112a: "CMPLEPS", 0xef8: "PUNPCKHDQ", 0x2407: "VAESDEC", 0x5ee: "FUCOM",
0x12a0: "VCMPORDPS", 0x19b1: "PSUBUSW", 0x1b4b: "PXOR", 0x1e15: "VPABSB", 0x24a: "WRMSR",
0x12ab: "VCMPEQ_UQPS", 0x22bc: "VFMADDSUB231PD", 0x7cf: "PFMAX", 0x16d3: "VCMPNEQ_OSSS",
0x224a: "VFNMADD213PD", 0x3b8: "MOVNTI", 0x7c6: "PFCMPGT", 0x2370: "VFNMADD231SS",
0x2456: "ROUNDPD", 0x12f3: "VCMPGTPS", 0xba5: "VRCPSS", 0x2140: "VFNMADD132SS",
0x144a: "VCMPNGEPD", 0x2215: "VFMSUB213PD", 0x1865: "VCMPNEQ_OSSD", 0x2685: "VPSLLDQ",
0x798: "PFCMPGE", 0x1485: "VCMPGTPD", 0x1a89: "CVTDQ2PD", 0x1217: "CMPLESD",
0xae: "JNS", 0xdde: "VDIVSD", 0xb7: "JNP", 0x250e: "EXTRACTPS", 0x1f49: "PMOVZXBQ",
0x9c: "JNZ", 0x5d8: "FCOMI", 0xeec: "VPUNPCKHWD", 0x1f34: "PMOVZXBD", 0x1ad0: "VMOVNTDQ",
0x1e7a: "PMOVSXWD", 0x10f8: "POPCNT", 0x8a: "JNO", 0x1c95: "FNSAVE", 0x1a5: "LOOP",
0xb0f: "VMOVMSKPS", 0x46b: "FLDL2T", 0x12d: "CMPS", 0x408: "FSUB", 0xdaa: "DIVPS",
0x1d21: "PHSUBD", 0x11b6: "CMPEQSS", 0x1e7: "CMC", 0xd05: "CVTTPS2DQ", 0xdb1: "DIVPD",
0xf62: "VMOVD", 0x104: "CALL FAR", 0x1d78: "PMULHRSW", 0x1d82: "VPMULHRSW",
0x1d10: "PHSUBW", 0x1205: "CMPEQSD", 0x3b2: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x1074: "VHADDPS", 0x26b3: "FXRSTOR64", 0x206a: "INVVPID", 0x20f: "LSL",
0x1663: "VCMPNEQ_USSS", 0x106b: "VHADDPD", 0x38b: "LSS", 0x20fd: "VFMSUB132PD",
0x121: "LAHF", 0x7f2: "PFACC", 0x809: "PFRCPIT2", 0xe2d: "VPUNPCKLBW", 0x7d6: "PFRCPIT1",
0x1f9d: "PCMPGTQ", 0x49f: "FYL2X", 0x181f: "VCMPORD_SSD", 0x1939: "PSRLD",
0x10e7: "SFENCE", 0xcfb: "CVTPS2DQ", 0x24b5: "PBLENDW", 0x21b4: "VFMSUBADD213PS",
0x2548: "VPINSRB", 0xe7c: "PCMPGTB", 0xea2: "PCMPGTD", 0x23dd: "VAESENC", 0x95d: "VMOVSHDUP",
0x25a2: "MPSADBW", 0x14ed: "VCMPNLE_UQPD", 0x710: "VMMCALL", 0x1035: "INSERTQ",
0x2258: "VFNMADD213SS", 0x9c5: "CVTPI2PD", 0x16f: "INT", 0x1d8d: "VPERMILPS",
0x1e2: "HLT", 0x2049: "PHMINPOSUW", 0x5b1: "FCMOVNU", 0x2073: "INVPCID", 0x7b: "INS",
0x647: "FCOMIP", 0x9bb: "CVTPI2PS", 0x2266: "VFNMADD213SD", 0xeb5: "PACKUSWB",
0xe4: "CBW", 0x721: "VMSAVE", 0x10e: "PUSHF", 0x64f: "NOT", 0x595: "FCMOVNB",
0x245: "NOP", 0x4e8: "FSQRT", 0x1d98: "VPERMILPD", 0x51: "INC", 0x239: "UD2",
0xfed: "VPCMPEQW", 0x261b: "PCMPISTRM", 0x1ed3: "VPCMPEQQ", 0x1153: "CMPNLEPS",
0x182c: "VCMPEQ_USSD", 0x1404: "VCMPUNORDPD", 0x5fd: "FADDP", 0x145: "RET",
0x1000: "VPCMPEQD", 0x1fc9: "VPMINSD", 0xfda: "VPCMPEQB", 0x1900: "ADDSUBPD",
0x22ac: "VFMADDSUB231PS", 0x169a: "VCMPEQ_USSS", 0x1d56: "PSIGNW", 0x1eae: "VPMOVSXDQ",
0x200d: "VPMAXSD", 0x35b: "SETG", 0x1ffc: "VPMAXSB", 0x327: "SETA", 0x306: "SETB",
0x26e5: "STMXCSR", 0x347: "SETL", 0x1abf: "MOVNTQ", 0x2f9: "SETO", 0xbd3: "ANDNPD",
0x110c: "BSR", 0x8c0: "VMOVDDUP", 0x1b42: "VPMAXSW", 0x1d67: "PSIGND", 0x33a: "SETP",
0x1d45: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x1596: "VCMPUNORDSS", 0xbcb: "ANDNPS",
0x2714: "VMXON", 0xbbb: "VANDPS", 0x6f3: "XSETBV", 0x1c3: "OUT", 0x67a: "LTR",
0x2576: "VPINSRD", 0x1105: "TZCNT", 0xa5d: "VCVTTSS2SI", 0x2674: "VPSRLDQ",
0x4c6: "FDECSTP", 0x266c: "PSRLDQ", 0x1873: "VCMPGE_OQSD", 0x267d: "PSLLDQ",
0x50f: "FCOS", 0x4b5: "FXTRACT", 0x16e1: "VCMPGE_OQSS", 0x1ee7: "VMOVNTDQA",
0x1523: "VCMPNGT_UQPD", 0x3f5: "FMUL", 0x13ca: "VCMPGT_OQPS", 0x60b: "FCOMPP",
0x780: "PF2ID", 0xf5: "CWD", 0x1330: "VCMPUNORD_SPS", 0x2ea: "CMOVLE", 0xfbd: "VPSHUFHW",
0x155c: "VCMPGT_OQPD", 0x1ce6: "PHADDSW", 0x779: "PF2IW", 0xa27: "VMOVNTPD",
0x401: "FCOMP", 0x8ca: "UNPCKLPS", 0x1bd5: "MASKMOVDQU", 0x560: "FCMOVBE",
0x14a8: "VCMPLT_OQPD", 0xe1a: "VMAXSD", 0x141c: "VCMPNLTPD", 0x98d: "PREFETCHT2",
0x981: "PREFETCHT1", 0x975: "PREFETCHT0", 0x8d4: "UNPCKLPD", 0xa47: "CVTTSS2SI",
0x65e: "DIV", 0x1ea4: "PMOVSXDQ", 0x160d: "VCMPGESS", 0xef: "CDQE", 0x26f8: "VSTMXCSR",
0x539: "FISUBR", 0x1fb8: "VPMINSB", 0x2208: "VFMSUB213PS", 0x1316: "VCMPLT_OQPS",
0x11c8: "CMPLESS", 0x1b04: "VPMINSW", 0x1c60: "FSTENV", 0x179f: "VCMPGESD",
0x1dda: "VPTEST", 0x532: "FISUB", 0x205: "STD", 0xf19: "VPACKSSDW", 0x3d: "XOR",
0xc85: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x26c8: "LDMXCSR", 0x1170: "CMPLTPD",
0xbed: "ORPS", 0x1efc: "VPACKUSDW", 0x61b: "FSUBP", 0x66f: "STR", 0x40e: "FSUBR",
0x1121: "CMPLTPS", 0x2313: "VFMADD231SD", 0x2723: "PAUSE", 0x1a93: "CVTPD2DQ",
0x372: "RSM", 0xb60: "VSQRTSD", 0xbf9: "VORPS", 0x2194: "VFMADDSUB213PS", 0x23d5: "AESENC",
0x143d: "VCMPEQ_UQPD", 0x908: "VUNPCKHPS", 0x1cf9: "PMADDUBSW", 0x135b: "VCMPNLE_UQPS",
0x1b6e: "VPSLLW", 0x1bcb: "MASKMOVQ", 0x1c8: "CALL", 0xb57: "VSQRTSS", 0x19e2: "PADDUSB",
0x1026: "VMREAD", 0x10db: "XSAVEOPT64", 0x913: "VUNPCKHPD", 0xd4e: "VSUBPS",
0xcdb: "VCVTSS2SD", 0x241c: "VAESDECLAST", 0x1085: "HSUBPS", 0xa9d: "VCVTSS2SI",
0x25e2: "VPBLENDVB", 0x17a9: "VCMPGTSD", 0x57a: "FILD", 0xae9: "VCOMISS", 0x107d: "HSUBPD",
0x23a8: "VFNMSUB231SS", 0x1a43: "VPSRAD", 0x1295: "VCMPNLEPS", 0x3e5: "SAL",
0x214: "SYSCALL", 0xb85: "VRSQRTSS", 0x257f: "VPINSRQ", 0x26ee: "WRGSBASE",
0xfb4: "VPSHUFD", 0x1e3b: "PMOVSXBW", 0x1a34: "VPSRAW", 0x1427: "VCMPNLEPD",
0x3ef: "FADD", 0x3ea: "SAR", 0x703: "XEND", 0x2649: "AESKEYGENASSIST", 0xf0f: "PACKSSDW",
0x21ee: "VFMADD213SS", 0xf80: "VMOVDQA", 0x8b5: "VMOVSLDUP", 0x4f8: "FRNDINT",
0x1966: "PMULLW", 0xdbf: "DIVSD", 0xafb: "MOVMSKPS", 0x201e: "VPMAXUW", 0xdce: "VDIVPD",
0x1e45: "VPMOVSXBW", 0x1e8f: "PMOVSXWQ", 0x2038: "PMULLD", 0xf89: "VMOVDQU",
0x229e: "VFNMSUB213SD", 0x297: "CMOVAE", 0x149b: "VCMPEQ_OSPD", 0xdc6: "VDIVPS",
0x93: "JAE", 0xb05: "MOVMSKPD", 0xdb8: "DIVSS", 0x1c9d: "FSAVE", 0x1eca: "PCMPEQQ",
0xfc7: "VPSHUFLW", 0xfe4: "PCMPEQW", 0x26db: "VLDMXCSR", 0x210a: "VFMSUB132SS",
0x11ac: "CMPORDPD", 0xb96: "RCPSS", 0x1b7d: "VPSLLD", 0x663: "IDIV", 0x1432: "VCMPORDPD",
0xfd1: "PCMPEQB", 0xff7: "PCMPEQD", 0x1b8c: "VPSLLQ", 0x1f53: "VPMOVZXBQ",
0x21c4: "VFMSUBADD213PD", 0x25d7: "VBLENDVPD", 0x115d: "CMPORDPS", 0xf24: "PUNPCKLQDQ",
0x19db: "VPAND", 0x146d: "VCMPNEQ_OQPD", 0x105b: "HADDPD", 0x191f: "VADDSUBPS",
0x18d7: "VSHUFPD", 0xd66: "VSUBSD", 0xb45: "VSQRTPS", 0x937: "MOVSHDUP", 0x237e: "VFNMADD231SD",
0x6bf: "VMLAUNCH", 0x1f13: "VMASKMOVPD", 0x1063: "HADDPS", 0x12db: "VCMPNEQ_OQPS",
0xe39: "PUNPCKLWD", 0x16b5: "VCMPNGT_UQSS", 0xb4e: "VSQRTPD", 0xd5e: "VSUBSS",
0x18ce: "VSHUFPS", 0x15a3: "VCMPNEQSS", 0x1b5f: "VLDDQU", 0x163a: "VCMPLT_OQSS",
0x2730: "RDRAND", 0x1b29: "PADDSW", 0x1376: "VCMPEQ_USPS", 0xbf3: "ORPD", 0x1a0f: "PANDN",
0x4a6: "FPTAN", 0x541: "FIDIV", 0x17cc: "VCMPLT_OQSD", 0x2702: "VMPTRLD", 0x2320: "VFMSUB231PS",
0x1735: "VCMPNEQSD", 0x1ec1: "VPMULDQ", 0x196: "LOOPNZ", 0x1272: "VCMPUNORDPS",
0x3e0: "SHR", 0x37c: "SHRD", 0x6db: "MONITOR", 0x23e6: "AESENCLAST", 0x844: "MOVSD",
0x18a4: "VPINSRW", 0x719: "VMLOAD", 0x91e: "MOVLHPS", 0x8ac: "VMOVLPD", 0x1977: "MOVQ2DQ",
0xb35: "SQRTSS", 0x258e: "VDPPS", 0xd40: "SUBSS", 0x3ab: "MOVSX", 0x941: "VMOVLHPS",
0x8a3: "VMOVLPS", 0xf03: "VPUNPCKHDQ", 0x1ab4: "VCVTPD2DQ", 0x3db: "SHL", 0x83d: "MOVSS",
0x256e: "PINSRQ", 0x787: "PFNACC", 0xf78: "MOVDQU", 0x80: "OUTS", 0x1bee: "PSUBB",
0x377: "BTS", 0x390: "BTR", 0x17f5: "VCMPNEQ_USSD", 0x68b: "SGDT", 0x2306: "VFMADD231SS",
0x501: "FSCALE", 0x1bfd: "PSUBW", 0x1198: "CMPNLTPD", 0x1ef2: "PACKUSDW", 0x20a: "LAR",
0x3a6: "BTC", 0x214e: "VFNMADD132SD", 0x1455: "VCMPNGTPD", 0x1f29: "VPMOVZXBW",
0x2117: "VFMSUB132SD", 0x23c4: "AESIMC", 0x3fb: "FCOM", 0x1f3e: "VPMOVZXBD",
0x1914: "VADDSUBPD", 0x1c8e: "FINIT", 0x11fb: "CMPORDSS", 0x231: "WBINVD",
0x19d5: "PAND", 0x24d1: "VPALIGNR", 0x124a: "CMPORDSD", 0x1b51: "VPXOR", 0xa1: "JBE",
0x45f: "FXAM", 0x10d1: "XSAVEOPT", 0x659: "MUL", 0x19cc: "VPMINUB", 0x1b31: "VPADDSW",
0x1b3a: "PMAXSW", 0x255b: "VINSERTPS", 0x13e6: "VCMPEQPD", 0x5e7: "FFREE",
0x1f07: "VMASKMOVPS", 0x18e0: "CMPXCHG8B", 0x2005: "PMAXSD", 0x1b20: "VPADDSB",
0x10: "PUSH", 0x25c0: "VPCLMULQDQ", 0x1254: "VCMPEQPS", 0x7e0: "PFRSQIT1",
0x2443: "ROUNDPS", 0x2ff: "SETNO", 0x6eb: "XGETBV", 0x1fc1: "PMINSD", 0x1c2a: "PADDB",
0x4be: "FPREM1", 0x200: "CLD", 0x51c: "FIMUL", 0xc0e: "XORPD", 0x1ec: "CLC",
0x42c: "FSTP", 0x24a2: "BLENDPD", 0x19f5: "PADDUSW", 0x1c86: "FNINIT", 0x319: "SETNZ",
0x1957: "PADDQ", 0xc07: "XORPS", 0x2290: "VFNMSUB213SS", 0x333: "SETNS", 0x515: "FIADD",
0x340: "SETNP", 0xf49: "VPUNPCKHQDQ", 0xd32: "SUBPS", 0x1236: "CMPNLTSD", 0x674: "LLDT",
0x222f: "VFMSUB213SD", 0x1dd3: "PTEST", 0x216a: "VFNMSUB132PD", 0x279: "GETSEC",
0x1d6f: "VPSIGND", 0x1ab: "JCXZ", 0x11e7: "CMPNLTSS", 0x34d: "SETGE", 0x1118: "CMPEQPS",
0x1bba: "PSADBW", 0x271b: "MOVSXD", 0x215c: "VFNMSUB132PS", 0x185: "AAD", 0x23f2: "VAESENCLAST",
0xf3d: "PUNPCKHQDQ", 0x87e: "MOVLPD", 0x19eb: "VPADDUSW", 0x12ce: "VCMPFALSEPS",
0x180: "AAM", 0xf30: "VPUNPCKLQDQ", 0xd7c: "MINSS", 0x1c48: "PADDD", 0x1460: "VCMPFALSEPD",
0xe44: "VPUNPCKLWD", 0x876: "MOVLPS", 0x72f: "CLGI", 0x4c: "AAS", 0x139: "LODS",
0x2d3: "CMOVNP", 0xd83: "MINSD", 0x1f6: "CLI", 0xa52: "CVTTSD2SI", 0x523: "FICOM",
0x1f1f: "PMOVZXBW", 0xc2c: "ADDPD", 0x760: "PREFETCHW", 0x133f: "VCMPNEQ_USPS",
0xc1d: "VXORPD", 0x1b0d: "POR", 0x16: "POP", 0x2437: "VPERM2F128", 0x19e: "LOOPZ",
0x1ac7: "MOVNTDQ", 0x1dc: "INT1", 0x382: "CMPXCHG", 0x1dfe: "VBROADCASTF128",
0x1515: "VCMPNGE_UQPD", 0x1cc4: "PHADDW", 0xc15: "VXORPS", 0x14d1: "VCMPNEQ_USPD",
0xc25: "ADDPS", 0x802: "PFMUL", 0x697: "LGDT", 0x67f: "VERR", 0x685: "VERW",
0x108d: "VHSUBPD", 0x196e: "VPMULLW", 0x84b: "VMOVUPS", 0x174: "INTO", 0x1c7f: "FCLEX",
0x1096: "VHSUBPS", 0xcbb: "CVTSD2SS", 0x47b: "FLDPI", 0x1e1d: "PABSW", 0xe0a: "VMAXPD",
0x1d3: "JMP FAR", 0xebf: "VPACKUSWB", 0x571: "FUCOMPP", 0x854: "VMOVUPD", 0x81c: "PSWAPD",
0x2485: "VROUNDSD", 0x1c39: "PADDW", 0x1b76: "PSLLD", 0x746: "SWAPGS", 0x886: "MOVSLDUP",
0x9cf: "CVTSI2SS", 0x17b3: "VCMPTRUESD", 0x11d1: "CMPUNORDSS", 0xd26: "VCVTTPS2DQ",
0xb3d: "SQRTSD", 0x1df0: "VBROADCASTSD", 0x1c0c: "PSUBD", 0xce: "TEST", 0x39a: "LGS",
0x1621: "VCMPTRUESS", 0x266: "SYSENTER", 0x9d9: "CVTSI2SD", 0x174b: "VCMPNLESD",
0x1dac: "VTESTPD", 0x98: "JZ", 0xdd6: "VDIVSS", 0xc00: "VORPD", 0xb3: "JP",
0xaa: "JS", 0xbc: "JL", 0xb72: "RSQRTSS", 0x1da3: "VTESTPS", 0x86: "JO", 0xe02: "VMAXPS",
0x199e: "PSUBUSB", 0xca: "JG", 0x1de2: "VBROADCASTSS", 0xa6: "JA", 0x8f: "JB",
0xe9: "CWDE", 0x13fa: "VCMPLEPD", 0x103e: "VMWRITE", 0x1268: "VCMPLEPS", 0x1989: "PMOVMSKB",
0x2551: "INSERTPS", 0x2604: "PCMPESTRI", 0x272a: "WAIT", 0x1531: "VCMPFALSE_OSPD",
0x25ed: "PCMPESTRM", 0xe50: "PUNPCKLDQ", 0xc6f: "MULSS", 0xd56: "VSUBPD", 0x1167: "CMPEQPD",
0x1791: "VCMPNEQ_OQSD", 0xaf2: "VCOMISD", 0xd9a: "VMINSS", 0x1c4f: "VPADDD",
0x258: "RDMSR", 0x1d5e: "VPSIGNW", 0x1b1: "JECXZ", 0xc76: "MULSD", 0x154: "ENTER",
0x2429: "MOVBE", 0x101c: "VZEROALL", 0x2738: "_3DNOW", 0xda2: "VMINSD", 0x15ff: "VCMPNEQ_OQSS",
0x7ea: "PFSUBR", 0x12e9: "VCMPGEPS", 0x19a7: "VPSUBUSB", 0x2347: "VFMSUB231SD",
0x2027: "PMAXUD", 0x268e: "FXSAVE", 0x580: "FISTTP", 0x147b: "VCMPGEPD", 0x248f: "BLENDPS",
0x171e: "VCMPLESD", 0x5a7: "FCMOVNBE", 0x233a: "VFMSUB231SS", 0x25cc: "VBLENDVPS",
0x25ab: "VMPSADBW", 0x19ba: "VPSUBUSW", 0x1714: "VCMPLTSD", 0x1edd: "MOVNTDQA",
0x18c6: "SHUFPD", 0xd39: "SUBPD", 0xb2d: "SQRTPD", 0x954: "VMOVHPD", 0x6b7: "VMCALL",
0x20c9: "VFMADD132PD", 0x15b: "LEAVE", 0x18be: "SHUFPS", 0x1309: "VCMPEQ_OSPS",
0x260f: "VPCMPESTRI", 0x1582: "VCMPLTSS", 0x25f8: "VPCMPESTRM", 0x20bc: "VFMADD132PS",
0x69d: "LIDT", 0x498: "F2XM1", 0x94b: "VMOVHPS", 0x1f88: "PMOVZXDQ", 0x1010: "VZEROUPPER",
0xb25: "SQRTPS", 0xbdb: "VANDNPS", 0x195e: "VPADDQ", 0x4d8: "FPREM", 0x1c40: "VPADDW",
0x24c8: "PALIGNR", 0x1fb0: "PMINSB", 0xe8f: "PCMPGTW", 0x36c: "SHLD", 0x14f: "LDS",
0x1c31: "VPADDB", 0x709: "VMRUN", 0x26a0: "RDFSBASE", 0xbe4: "VANDNPD", 0x190: "XLAT",
0xd4: "XCHG", 0x4cf: "FINCSTP", 0x1980: "MOVDQ2Q", 0x1afc: "PMINSW", 0x6a3: "SMSW",
0x1d4d: "VPSIGNB", 0x10b7: "XRSTOR", 0x24ab: "VBLENDPD", 0xc0: "JGE", 0x134d: "VCMPNLT_UQPS",
0x1756: "VCMPORDSD", 0x2498: "VBLENDPS", 0x459: "FTST", 0x1a7e: "CVTTPD2DQ",
0x15c4: "VCMPORDSS", 0x14df: "VCMPNLT_UQPD", 0x2178: "VFNMSUB132SS", 0x10bf: "XRSTOR64",
0x29: "AND", 0xb7b: "VRSQRTPS", 0x10ef: "CLFLUSH", 0x1cb3: "PSHUFB", 0x432: "FLDENV",
0xda: "MOV", 0xf9a: "PSHUFD", 0xc5: "JLE", 0x5c0: "FEDISI", 0x6fb: "VMFUNC",
0xe98: "VPCMPGTW", 0x7f9: "PFCMPEQ", 0x168d: "VCMPORD_SSS", 0xf92: "PSHUFW",
0x24e3: "VPEXTRB", 0x1aa9: "VCVTDQ2PD", 0xf69: "VMOVQ", 0x473: "FLDL2E", 0x24fc: "VPEXTRD",
0x1d18: "VPHSUBW", 0x2274: "VFNMSUB213PS", 0x21e1: "VFMADD213PD", 0x729: "STGI",
0x4ad: "FPATAN", 0x2505: "VPEXTRQ", 0x427: "FST", 0x168: "INT 3", 0x588: "FIST",
0x270b: "VMCLEAR", 0x1e65: "PMOVSXBQ", 0x42: "AAA", 0x1d29: "VPHSUBD", 0xa31: "CVTTPS2PI",
0x113f: "CMPNEQPS", 0x154f: "VCMPGE_OQPD", 0x1b58: "LDDQU", 0xb69: "RSQRTPS",
0xc49: "VADDPD", 0x7a8: "PFRCP", 0xcb1: "CVTSS2SD", 0x2186: "VFNMSUB132SD",
0x622: "FDIVRP", 0x631: "FBLD", 0x361: "CPUID", 0x251: "RDTSC", 0x24be: "VPBLENDW",
0xd1b: "VCVTPS2DQ", 0x1b12: "VPOR", 0xc41: "VADDPS", 0x76b: "PI2FW", 0xd6e: "MINPS",
0x17bf: "VCMPEQ_OSSD", 0x1b9d: "VPMULUDQ", 0xdfb: "MAXSD", 0x2040: "VPMULLD",
0x548: "FIDIVR", 0xac5: "VUCOMISS", 0x890: "MOVDDUP", 0x1cbb: "VPSHUFB", 0x1d32: "PHSUBSW",
0x263d: "VPCMPISTRI", 0xdf4: "MAXSS", 0x1a25: "VPAVGB", 0x16c3: "VCMPFALSE_OSSS",
0xd75: "MINPD", 0x4df: "FYL2XP1", 0xacf: "VUCOMISD", 0x239a: "VFNMSUB231PD",
0x1839: "VCMPNGE_UQSD", 0xc3a: "ADDSD", 0x6d3: "VMXOFF", 0x1948: "PSRLQ", 0x127f: "VCMPNEQPS",
0x192a: "PSRLW", 0x1a3c: "PSRAD", 0x691: "SIDT", 0xe67: "PACKSSWB", 0x109f: "XSAVE",
0x1411: "VCMPNEQPD", 0xfa: "CDQ", 0xc33: "ADDSS", 0x16a7: "VCMPNGE_UQSS", 0x2430: "CRC32",
0x23cc: "VAESIMC", 0x1ff4: "PMAXSB", 0x2519: "VEXTRACTPS", 0x1803: "VCMPNLT_UQSD",
0x1bf5: "VPSUBB", 0x1f7d: "VPMOVZXWQ", 0x13af: "VCMPNEQ_OSPS", 0xa0b: "MOVNTSS",
0x2532: "VEXTRACTF128", 0x1b18: "PADDSB", 0x75: "IMUL", 0x3d6: "RCR", 0x14c2: "VCMPUNORD_SPD",
0x3d1: "RCL", 0xa14: "MOVNTSD", 0x1541: "VCMPNEQ_OSPD", 0x1671: "VCMPNLT_UQSS",
0xd47: "SUBSD", 0x13f: "SCAS", 0x25b5: "PCLMULQDQ", 0x7af: "PFRSQRT", 0x2566: "PINSRD",
0x613: "FSUBRP", 0x5b: "PUSHA", 0x1a06: "VPMAXUB", 0x1133: "CMPUNORDPS", 0x202f: "VPMAXUD",
0x453: "FABS", 0x1e6f: "VPMOVSXBQ", 0x148f: "VCMPTRUEPD", 0x23e: "FEMMS", 0x162d: "VCMPEQ_OSSS",
0x21fb: "VFMADD213SD", 0x1e5a: "VPMOVSXBD", 0x1182: "CMPUNORDPD", 0x18f7: "VMPTRST",
0x18eb: "CMPXCHG16B", 0x12fd: "VCMPTRUEPS", 0x12c3: "VCMPNGTPS", 0x1c77: "FNCLEX",
0x122c: "CMPNEQSD", 0x1761: "VCMPEQ_UQSD", 0x569: "FCMOVU", 0x102e: "EXTRQ",
0x2595: "DPPD", 0x2e2: "CMOVGE", 0x2540: "PINSRB", 0x15cf: "VCMPEQ_UQSS", 0x1d04: "VPMADDUBSW",
0x11dd: "CMPNEQSS", 0x22f9: "VFMADD231PD", 0x509: "FSIN", 0x1bf: "IN", 0x558: "FCMOVE",
0x43a: "FLDCW", 0x2588: "DPPS", 0x550: "FCMOVB", 0x1931: "VPSRLW", 0x10af: "LFENCE",
0xa93: "CVTSD2SI", 0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x194f: "VPSRLQ", 0x604: "FMULP",
0x9b2: "VMOVAPD", 0x1647: "VCMPLE_OQSS", 0x2c4: "CMOVNS", 0x59e: "FCMOVNE",
0x288: "CMOVNO", 0x1a75: "VPMULHW", 0x1940: "VPSRLD", 0x1051: "CVTPS2PH", 0xa75: "CVTPS2PI",
0x1cd5: "PHADDD", 0xc9d: "CVTPS2PD", 0x1e24: "VPABSW", 0x17d9: "VCMPLE_OQSD",
0x9a9: "VMOVAPS", 0x1c04: "VPSUBW", 0x813: "PMULHRW", 0x999: "MOVAPS", 0x7a1: "PFMIN",
0xf56: "MOVD", 0x927: "MOVHPS", 0xc61: "MULPS", 0x125e: "VCMPLTPS", 0x368: "BT",
0x9a1: "MOVAPD", 0x1383: "VCMPNGE_UQPS", 0x1b8: "JRCXZ", 0xc68: "MULPD", 0x127: "MOVS",
0x6af: "INVLPG", 0xf5c: "MOVQ", 0xd92: "VMINPD", 0x1e2c: "PABSD", 0x11b: "SAHF",
0x13d7: "VCMPTRUE_USPS", 0x772: "PI2FD", 0x1e0e: "PABSB", 0x1a16: "VPANDN",
0xe5b: "VPUNPCKLDQ", 0x62a: "FDIVP", 0x1c1b: "PSUBQ", 0x41b: "FDIVR", 0x415: "FDIV",
0x1569: "VCMPTRUE_USPD", 0x756: "PREFETCH", 0x100a: "EMMS", 0xd8a: "VMINPS",
0x22ec: "VFMADD231PS", 0x2282: "VFNMSUB213PD", 0xa89: "CVTSS2SI", 0x92f: "MOVHPD",
0x29f: "CMOVZ", 0x1a52: "VPAVGW", 0xff: "CQO", 0x1c13: "VPSUBD", 0x2cc: "CMOVP",
0x1578: "VCMPEQSS", 0x2bd: "CMOVS", 0x1e50: "PMOVSXBD", 0x2472: "VROUNDSS",
0x1c22: "VPSUBQ", 0x2db: "CMOVL", 0x190a: "ADDSUBPS", 0x281: "CMOVO", 0x2b6: "CMOVA",
0x290: "CMOVB", 0xeca: "PUNPCKHBW", 0x2632: "PCMPISTRI", 0x2f2: "CMOVG", 0x1993: "VPMOVMSKB",
0x2410: "AESDECLAST", 0x835: "MOVUPD", 0x20ac: "VFMSUBADD132PD", 0x1bc2: "VPSADBW",
0x245f: "VROUNDPD", 0x6a9: "LMSW", 0x2062: "INVEPT", 0x39f: "MOVZX", 0xbad: "ANDPS",
0x209c: "VFMSUBADD132PS", 0x82d: "MOVUPS", 0x1617: "VCMPGTSS", 0x1a5a: "PMULHUW",
0x259b: "VDPPD", 0x24ec: "PEXTRD", 0x15f2: "VCMPFALSESS", 0x26be: "RDGSBASE",
0x1b: "OR", 0x18b5: "VPEXTRW", 0x1ae2: "VPSUBSB", 0x26aa: "FXRSTOR", 0x21d: "CLTS",
0x1847: "VCMPNGT_UQSD", 0x15e7: "VCMPNGTSS", 0x5df: "FRSTOR", 0x1784: "VCMPFALSESD",
0x48a: "FLDLN2", 0x2525: "VINSERTF128", 0x1af3: "VPSUBSW", 0x1b94: "PMULUDQ",
0x56: "DEC", 0x139f: "VCMPFALSE_OSPS", 0x422: "FLD", 0x1f92: "VPMOVZXDQ", 0x2469: "ROUNDSS",
0x9e3: "VCVTSI2SS", 0x18ad: "PEXTRW", 0x2696: "FXSAVE64", 0x3c7: "ROL", 0x20e3: "VFMADD132SD",
0x1179: "CMPLEPD", 0xce6: "VCVTSD2SS", 0x5f5: "FUCOMP", 0x1ce: "JMP", 0x170a: "VCMPEQSD",
0xcf1: "CVTDQ2PS", 0x16ee: "VCMPGT_OQSS", 0x5d0: "FUCOMI", 0x1111: "LZCNT",
0xb9d: "VRCPPS", 0x19fe: "PMAXUB", 0x1cdd: "VPHADDD", 0x9ee: "VCVTSI2SD", 0x1880: "VCMPGT_OQSD",
0x3cc: "ROR", 0x22b: "INVD", 0xaa8: "VCVTSD2SI", 0x23ff: "AESDEC", 0x1240: "CMPNLESD",
0x354: "SETLE", 0x22cc: "VFMSUBADD231PS", 0x2354: "VFNMADD231PS", 0x10a6: "XSAVE64",
0xee1: "PUNPCKHWD", 0x1e84: "VPMOVSXWD", 0xca7: "CVTPD2PS", 0x899: "VMOVHLPS",
0x22dc: "VFMSUBADD231PD", 0xa7f: "CVTPD2PI", 0x11f1: "CMPNLESS", 0x1eb9: "PMULDQ",
0x1e99: "VPMOVSXWQ", 0x1740: "VCMPNLTSD", 0x20f0: "VFMSUB132PS", 0x2362: "VFNMADD231PD",
0x1cac: "FSTSW", 0x74e: "RDTSCP", 0x10c9: "MFENCE", 0x20d6: "VFMADD132SS",
0x1fe3: "PMINUD", 0x5ba: "FENI", 0x68: "BOUND", 0x244c: "VROUNDPS", 0xfab: "PSHUFLW",
0xc8d: "VMULSS", 0x1855: "VCMPFALSE_OSSD", 0xd10: "VCVTDQ2PS", 0x158c: "VCMPLESS",
0x447: "FNOP", 0x1149: "CMPNLTPS", 0x128a: "VCMPNLTPS", 0x482: "FLDLG2", 0x223: "SYSRET",
0x1c70: "FSTCW", 0x2222: "VFMSUB213SS", 0x735: "SKINIT", 0xbc3: "VANDPD", 0x492: "FLDZ",
0x33: "SUB", 0x1ccc: "VPHADDW", 0x654: "NEG", 0x1fd2: "PMINUW", 0xded: "MAXPD",
0x1369: "VCMPORD_SPS", 0x133: "STOS", 0x23b6: "VFNMSUB231SD", 0x1728: "VCMPUNORDSD",
0x824: "PAVGUSB", 0x14fb: "VCMPORD_SPD", 0xde6: "MAXPS", 0x19c4: "PMINUB",
0x1be1: "VMASKMOVDQU", 0x637: "FBSTP", 0x189c: "PINSRW", 0x1f68: "VPMOVZXWD",
0x1fda: "VPMINUW", 0x1811: "VCMPNLE_UQSD", 0x18a: "SALC", 0x24db: "PEXTRB",
0x8de: "VUNPCKLPS", 0x167f: "VCMPNLE_UQSS", 0xf70: "MOVDQA", 0x15ae: "VCMPNLTSS",
0x1b85: "PSLLQ", 0xa1d: "VMOVNTPS", 0x1feb: "VPMINUD", 0x968: "PREFETCHNTA",
0x8e9: "VUNPCKLPD", 0x1047: "CVTPH2PS", 0x265a: "VAESKEYGENASSIST", 0x1aeb: "PSUBSW",
0x176e: "VCMPNGESD", 0x1c57: "FNSTENV", 0x1ca4: "FNSTSW", 0x118e: "CMPNEQPD",
0x1a4b: "PAVGW", 0xa02: "MOVNTPD", 0x1508: "VCMPEQ_USPD", 0x5c8: "FSETPM",
0x1dbf: "BLENDVPS", 0x21a4: "VFMADDSUB213PD", 0xb: "ADD", 0x15dc: "VCMPNGESS",
0x1f: "ADC", 0x1ada: "PSUBSB", 0x1dc9: "BLENDVPD", 0xed5: "VPUNPCKHBW", 0x25f: "RDPMC",
0x9f9: "MOVNTPS", 0x1100: "BSF", 0x13f0: "VCMPLTPD", 0x1a1e: "PAVGB", 0xdf: "LEA",
0x1a9d: "VCVTTPD2DQ", 0xe85: "VPCMPGTB", 0xeab: "VPCMPGTD", 0x465: "FLD1",
0x1bb0: "VPMADDWD", 0x17e6: "VCMPUNORD_SSD", 0x14a: "LES", 0x313: "SETZ", 0x1fa6: "VPCMPGTQ",
0xc95: "VMULSD", 0x21d4: "VFMADD213PS", 0x15b9: "VCMPNLESS", 0x86d: "MOVHLPS",
0x2055: "VPHMINPOSUW", 0x1e33: "VPABSD", 0x1a2d: "PSRAW", 0x7bf: "PFADD", 0x208c: "VFMADDSUB132PD",
0xae1: "COMISD", 0x13bd: "VCMPGE_OQPS", 0xe12: "VMAXSS", 0x1220: "CMPUNORDSD",
0x4ef: "FSINCOS", 0xad9: "COMISS", 0x207c: "VFMADDSUB132PS", 0xb8f: "RCPPS",
0x2132: "VFNMADD132PD", 0x441: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcc5: "VCVTPS2PD",
0x1ba7: "PMADDWD", 0xbb4: "ANDPD", 0x1323: "VCMPLE_OQPS", 0x1779: "VCMPNGTSD",
0x238c: "VFNMSUB231PS", 0x63e: "FUCOMIP", 0xc7d: "VMULPS", 0x2124: "VFNMADD132PS",
0x26d1: "WRFSBASE", 0x38: "DAS", 0x14b5: "VCMPLE_OQPD", 0x17a: "IRET", 0x3c0: "BSWAP",
0xe22: "PUNPCKLBW", 0x2016: "PMAXUW", 0x2626: "VPCMPISTRM", 0x1b67: "PSLLW",
0x1654: "VCMPUNORD_SSS", 0x223c: "VFNMADD213PS", 0xa69: "VCVTTSD2SI", 0x232d: "VFMSUB231PD",
0x1391: "VCMPNGT_UQPS", 0x1c68: "FNSTCW", 0x247c: "ROUNDSD", 0x11a2: "CMPNLEPD",
0x24f4: "PEXTRQ", 0x1a6d: "PMULHW", 0x1cef: "VPHADDSW", 0x58e: "FISTP", 0x1f73: "PMOVZXWQ",
0xcd0: "VCVTPD2PS", 0x16fb: "VCMPTRUE_USSS", 0xc59: "VADDSD", 0x1db5: "PBLENDVB",
0x6c9: "VMRESUME", 0xabc: "UCOMISD", 0x1f5e: "PMOVZXWD", 0xa3c: "CVTTPD2PI",
0xab3: "UCOMISS", 0xe71: "VPACKSSWB", 0xc51: "VADDSS", 0xfa2: "PSHUFHW", 0x188d: "VCMPTRUE_USSD",
0x6e4: "MWAIT"
}

Registers = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W",
"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B",
"SPL", "BPL", "SIL", "DIL",
"ES", "CS", "SS", "DS", "FS", "GS",
"RIP",
"ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7",
"MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7",
"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
"YMM0", "YMM1", "YMM2", "YMM3", "YMM4", "YMM5", "YMM6", "YMM7", "YMM8", "YMM9", "YMM10", "YMM11", "YMM12", "YMM13", "YMM14", "YMM15",
"CR0", "", "CR2", "CR3", "CR4", "", "", "", "CR8",
"DR0", "DR1", "DR2", "DR3", "", "", "DR6", "DR7"]

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
DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | \
    DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV)

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
                asm += " " + di.operands.p
            pydi = (di.offset, di.size, asm, di.instructionHex.p)
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
"FC_CMOV"
]

def _getOpSize(flags):
    return ((flags >> 7) & 3)

def _getISC(metaflags):
    realvalue = ((metaflags >> 3) & 0x1f)
    return InstructionSetClasses[realvalue]

def _getFC(metaflags):
    realvalue = (metaflags & 0x7)
    try:
        return FlowControlFlags[realvalue]
    except IndexError:
        print ("Bad meta-flags: %d", realvalue)
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
        self.instructionClass = _getISC(metas)
        self.flowControl = _getFC(metas)

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
    instruction_off = 0

    while codeLen > 0:
        
        usedInstructionsCount = c_uint(0)
        codeInfo = _CodeInfo(_OffsetType(codeOffset), _OffsetType(0), cast(p_code, c_char_p), codeLen, dt, features)
        status = internal_decompose(byref(codeInfo), byref(result), MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        delta = 0
        for index in range(used):
            di = result[index]
            yield Instruction(di, code[instruction_off : instruction_off + di.size], dt)
            delta += di.size
            instruction_off += di.size

        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, instruction_off)
        codeLen    = codeLen - delta
        
        if (features & DF_STOP_ON_FLOW_CONTROL) != 0:
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
