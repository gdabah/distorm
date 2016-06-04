# :[diStorm3}: Python binding
# Based on diStorm64 Python binding by Mario Vilas
# Initial support for decompose API added by Roee Shenberg
# Licensed under BSD in 2016.
#
# Compatible with Python2.6 and above.
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
]

from ctypes import *
from os.path import split, join
from os import name as os_name
import sys

if sys.version_info[0] >= 3:
    xrange = range

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

Mnemonics = {
0x679: "SLDT", 0x62: "POPA", 0x904: "UNPCKHPS", 0x115: "POPF", 0x11cf: "CMPLTSS",
0x875: "VMOVSD", 0x79f: "PFPNACC", 0xb2a: "VMOVMSKPD", 0x74d: "INVLPGA", 0x90e: "UNPCKHPD",
0x270: "SYSEXIT", 0x7c8: "PFSUB", 0x121e: "CMPLTSD", 0x1a73: "VPMULHUW", 0x1d4b: "VPHSUBSW",
0x12c8: "VCMPNGEPS", 0x86d: "VMOVSS", 0x6f: "ARPL", 0x53a: "FICOMP", 0x162: "RETF",
0x45d: "FCHS", 0x113a: "CMPLEPS", 0xf08: "PUNPCKHDQ", 0x2417: "VAESDEC", 0x5fe: "FUCOM",
0x12b0: "VCMPORDPS", 0x19c1: "PSUBUSW", 0x1b5b: "PXOR", 0x1e25: "VPABSB", 0x24a: "WRMSR",
0x12bb: "VCMPEQ_UQPS", 0x22cc: "VFMADDSUB231PD", 0x7df: "PFMAX", 0x16e3: "VCMPNEQ_OSSS",
0x225a: "VFNMADD213PD", 0x3b8: "MOVNTI", 0x7d6: "PFCMPGT", 0x2380: "VFNMADD231SS",
0x2466: "ROUNDPD", 0x1303: "VCMPGTPS", 0xbb5: "VRCPSS", 0x2150: "VFNMADD132SS",
0x145a: "VCMPNGEPD", 0x2225: "VFMSUB213PD", 0x1875: "VCMPNEQ_OSSD", 0x2695: "VPSLLDQ",
0x7a8: "PFCMPGE", 0x1495: "VCMPGTPD", 0x1a99: "CVTDQ2PD", 0x1227: "CMPLESD",
0xae: "JNS", 0xdee: "VDIVSD", 0xb7: "JNP", 0x251e: "EXTRACTPS", 0x1f59: "PMOVZXBQ",
0x9c: "JNZ", 0x5e8: "FCOMI", 0xefc: "VPUNPCKHWD", 0x1f44: "PMOVZXBD", 0x1ae0: "VMOVNTDQ",
0x1e8a: "PMOVSXWD", 0x1108: "POPCNT", 0x8a: "JNO", 0x1ca5: "FNSAVE", 0x1a5: "LOOP",
0xb1f: "VMOVMSKPS", 0x47b: "FLDL2T", 0x12d: "CMPS", 0x418: "FSUB", 0xdba: "DIVPS",
0x1d31: "PHSUBD", 0x11c6: "CMPEQSS", 0x1e7: "CMC", 0xd15: "CVTTPS2DQ", 0xdc1: "DIVPD",
0xf72: "VMOVD", 0x104: "CALL FAR", 0x1d88: "PMULHRSW", 0x1d92: "VPMULHRSW",
0x1d20: "PHSUBW", 0x1215: "CMPEQSD", 0x3b2: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x1084: "VHADDPS", 0x26c3: "FXRSTOR64", 0x207a: "INVVPID", 0x20f: "LSL",
0x1673: "VCMPNEQ_USSS", 0x107b: "VHADDPD", 0x38b: "LSS", 0x210d: "VFMSUB132PD",
0x121: "LAHF", 0x802: "PFACC", 0x819: "PFRCPIT2", 0xe3d: "VPUNPCKLBW", 0x7e6: "PFRCPIT1",
0x1fad: "PCMPGTQ", 0x4af: "FYL2X", 0x182f: "VCMPORD_SSD", 0x1949: "PSRLD",
0x10f7: "SFENCE", 0xd0b: "CVTPS2DQ", 0x24c5: "PBLENDW", 0x21c4: "VFMSUBADD213PS",
0xe8c: "PCMPGTB", 0xeb2: "PCMPGTD", 0x23ed: "VAESENC", 0x96d: "VMOVSHDUP",
0x25b2: "MPSADBW", 0x14fd: "VCMPNLE_UQPD", 0x720: "VMMCALL", 0x1045: "INSERTQ",
0x2268: "VFNMADD213SS", 0x9d5: "CVTPI2PD", 0x16f: "INT", 0x1d9d: "VPERMILPS",
0x1e2: "HLT", 0x2059: "PHMINPOSUW", 0x5c1: "FCMOVNU", 0x2083: "INVPCID", 0x7b: "INS",
0x657: "FCOMIP", 0x9cb: "CVTPI2PS", 0x2276: "VFNMADD213SD", 0xec5: "PACKUSWB",
0xe4: "CBW", 0x731: "VMSAVE", 0x10e: "PUSHF", 0x65f: "NOT", 0x5a5: "FCMOVNB",
0x245: "NOP", 0x4f8: "FSQRT", 0x1da8: "VPERMILPD", 0x51: "INC", 0x239: "UD2",
0xffd: "VPCMPEQW", 0x262b: "PCMPISTRM", 0x1ee3: "VPCMPEQQ", 0x1163: "CMPNLEPS",
0x183c: "VCMPEQ_USSD", 0x1414: "VCMPUNORDPD", 0x60d: "FADDP", 0x145: "RET",
0x1010: "VPCMPEQD", 0x1fd9: "VPMINSD", 0x2558: "VPINSRB", 0xfea: "VPCMPEQB",
0x1910: "ADDSUBPD", 0x22bc: "VFMADDSUB231PS", 0x16aa: "VCMPEQ_USSS", 0x1d66: "PSIGNW",
0x1ebe: "VPMOVSXDQ", 0x201d: "VPMAXSD", 0x35b: "SETG", 0x200c: "VPMAXSB", 0x327: "SETA",
0x306: "SETB", 0x26f5: "STMXCSR", 0x347: "SETL", 0x1acf: "MOVNTQ", 0x2f9: "SETO",
0xbe3: "ANDNPD", 0x111c: "BSR", 0x8d0: "VMOVDDUP", 0x1b52: "VPMAXSW", 0x1d77: "PSIGND",
0x33a: "SETP", 0x1d55: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x15a6: "VCMPUNORDSS",
0xbdb: "ANDNPS", 0x2724: "VMXON", 0xbcb: "VANDPS", 0x703: "XSETBV", 0x1c3: "OUT",
0x68a: "LTR", 0x2586: "VPINSRD", 0x1115: "TZCNT", 0xa6d: "VCVTTSS2SI", 0x2684: "VPSRLDQ",
0x4d6: "FDECSTP", 0x267c: "PSRLDQ", 0x1883: "VCMPGE_OQSD", 0x268d: "PSLLDQ",
0x51f: "FCOS", 0x4c5: "FXTRACT", 0x16f1: "VCMPGE_OQSS", 0x1ef7: "VMOVNTDQA",
0x1533: "VCMPNGT_UQPD", 0x405: "FMUL", 0x13da: "VCMPGT_OQPS", 0x61b: "FCOMPP",
0x790: "PF2ID", 0xf5: "CWD", 0x1340: "VCMPUNORD_SPS", 0x2ea: "CMOVLE", 0xfcd: "VPSHUFHW",
0x156c: "VCMPGT_OQPD", 0x1cf6: "PHADDSW", 0x789: "PF2IW", 0xa37: "VMOVNTPD",
0x411: "FCOMP", 0x8da: "UNPCKLPS", 0x1be5: "MASKMOVDQU", 0x570: "FCMOVBE",
0x14b8: "VCMPLT_OQPD", 0xe2a: "VMAXSD", 0x142c: "VCMPNLTPD", 0x99d: "PREFETCHT2",
0x991: "PREFETCHT1", 0x985: "PREFETCHT0", 0x8e4: "UNPCKLPD", 0xa57: "CVTTSS2SI",
0x66e: "DIV", 0x1eb4: "PMOVSXDQ", 0x161d: "VCMPGESS", 0xef: "CDQE", 0x2708: "VSTMXCSR",
0x549: "FISUBR", 0x1fc8: "VPMINSB", 0x2218: "VFMSUB213PS", 0x1326: "VCMPLT_OQPS",
0x11d8: "CMPLESS", 0x1b14: "VPMINSW", 0x1c70: "FSTENV", 0x17af: "VCMPGESD",
0x1dea: "VPTEST", 0x542: "FISUB", 0x205: "STD", 0xf29: "VPACKSSDW", 0x3d: "XOR",
0xc95: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x26d8: "LDMXCSR", 0x1180: "CMPLTPD",
0xbfd: "ORPS", 0x1f0c: "VPACKUSDW", 0x62b: "FSUBP", 0x67f: "STR", 0x41e: "FSUBR",
0x1131: "CMPLTPS", 0x2323: "VFMADD231SD", 0x2733: "PAUSE", 0x1aa3: "CVTPD2DQ",
0x372: "RSM", 0xb70: "VSQRTSD", 0xc09: "VORPS", 0x21a4: "VFMADDSUB213PS", 0x23e5: "AESENC",
0x144d: "VCMPEQ_UQPD", 0x918: "VUNPCKHPS", 0x1d09: "PMADDUBSW", 0x136b: "VCMPNLE_UQPS",
0x1b7e: "VPSLLW", 0x1bdb: "MASKMOVQ", 0x1c8: "CALL", 0xb67: "VSQRTSS", 0x19f2: "PADDUSB",
0x1036: "VMREAD", 0x10eb: "XSAVEOPT64", 0x923: "VUNPCKHPD", 0xd5e: "VSUBPS",
0xceb: "VCVTSS2SD", 0x242c: "VAESDECLAST", 0x1095: "HSUBPS", 0xaad: "VCVTSS2SI",
0x25f2: "VPBLENDVB", 0x17b9: "VCMPGTSD", 0x58a: "FILD", 0xaf9: "VCOMISS", 0x108d: "HSUBPD",
0x23b8: "VFNMSUB231SS", 0x1a53: "VPSRAD", 0x12a5: "VCMPNLEPS", 0x3e5: "SAL",
0x214: "SYSCALL", 0xb95: "VRSQRTSS", 0x258f: "VPINSRQ", 0x26fe: "WRGSBASE",
0xfc4: "VPSHUFD", 0x1e4b: "PMOVSXBW", 0x1a44: "VPSRAW", 0x1437: "VCMPNLEPD",
0x3ff: "FADD", 0x3ea: "SAR", 0x713: "XEND", 0x2659: "AESKEYGENASSIST", 0xf1f: "PACKSSDW",
0x21fe: "VFMADD213SS", 0xf90: "VMOVDQA", 0x8c5: "VMOVSLDUP", 0x508: "FRNDINT",
0x1976: "PMULLW", 0xdcf: "DIVSD", 0xb0b: "MOVMSKPS", 0x202e: "VPMAXUW", 0xdde: "VDIVPD",
0x1e55: "VPMOVSXBW", 0x1e9f: "PMOVSXWQ", 0x2048: "PMULLD", 0xf99: "VMOVDQU",
0x22ae: "VFNMSUB213SD", 0x297: "CMOVAE", 0x14ab: "VCMPEQ_OSPD", 0xdd6: "VDIVPS",
0x93: "JAE", 0xb15: "MOVMSKPD", 0xdc8: "DIVSS", 0x1cad: "FSAVE", 0x1eda: "PCMPEQQ",
0xfd7: "VPSHUFLW", 0xff4: "PCMPEQW", 0x26eb: "VLDMXCSR", 0x211a: "VFMSUB132SS",
0x11bc: "CMPORDPD", 0xba6: "RCPSS", 0x1b8d: "VPSLLD", 0x673: "IDIV", 0x1442: "VCMPORDPD",
0xfe1: "PCMPEQB", 0x1007: "PCMPEQD", 0x1b9c: "VPSLLQ", 0x1f63: "VPMOVZXBQ",
0x21d4: "VFMSUBADD213PD", 0x25e7: "VBLENDVPD", 0x116d: "CMPORDPS", 0xf34: "PUNPCKLQDQ",
0x19eb: "VPAND", 0x147d: "VCMPNEQ_OQPD", 0x106b: "HADDPD", 0x192f: "VADDSUBPS",
0x18e7: "VSHUFPD", 0xd76: "VSUBSD", 0xb55: "VSQRTPS", 0x947: "MOVSHDUP", 0x238e: "VFNMADD231SD",
0x6cf: "VMLAUNCH", 0x1f23: "VMASKMOVPD", 0x1073: "HADDPS", 0x12eb: "VCMPNEQ_OQPS",
0xe49: "PUNPCKLWD", 0x16c5: "VCMPNGT_UQSS", 0xb5e: "VSQRTPD", 0xd6e: "VSUBSS",
0x18de: "VSHUFPS", 0x15b3: "VCMPNEQSS", 0x1b6f: "VLDDQU", 0x164a: "VCMPLT_OQSS",
0x2740: "RDRAND", 0x1b39: "PADDSW", 0x1386: "VCMPEQ_USPS", 0xc03: "ORPD", 0x1a1f: "PANDN",
0x4b6: "FPTAN", 0x551: "FIDIV", 0x17dc: "VCMPLT_OQSD", 0x2712: "VMPTRLD", 0x2330: "VFMSUB231PS",
0x1745: "VCMPNEQSD", 0x1ed1: "VPMULDQ", 0x196: "LOOPNZ", 0x1282: "VCMPUNORDPS",
0x3e0: "SHR", 0x37c: "SHRD", 0x6eb: "MONITOR", 0x3ef: "XABORT", 0x23f6: "AESENCLAST",
0x854: "MOVSD", 0x18b4: "VPINSRW", 0x729: "VMLOAD", 0x92e: "MOVLHPS", 0x8bc: "VMOVLPD",
0x1987: "MOVQ2DQ", 0xb45: "SQRTSS", 0x259e: "VDPPS", 0xd50: "SUBSS", 0x3ab: "MOVSX",
0x951: "VMOVLHPS", 0x8b3: "VMOVLPS", 0xf13: "VPUNPCKHDQ", 0x1ac4: "VCVTPD2DQ",
0x3db: "SHL", 0x84d: "MOVSS", 0x257e: "PINSRQ", 0x797: "PFNACC", 0xf88: "MOVDQU",
0x80: "OUTS", 0x1bfe: "PSUBB", 0x377: "BTS", 0x390: "BTR", 0x1805: "VCMPNEQ_USSD",
0x69b: "SGDT", 0x2316: "VFMADD231SS", 0x511: "FSCALE", 0x1c0d: "PSUBW", 0x11a8: "CMPNLTPD",
0x1f02: "PACKUSDW", 0x20a: "LAR", 0x3a6: "BTC", 0x215e: "VFNMADD132SD", 0x1465: "VCMPNGTPD",
0x1f39: "VPMOVZXBW", 0x2127: "VFMSUB132SD", 0x23d4: "AESIMC", 0x40b: "FCOM",
0x1f4e: "VPMOVZXBD", 0x1924: "VADDSUBPD", 0x1c9e: "FINIT", 0x120b: "CMPORDSS",
0x231: "WBINVD", 0x19e5: "PAND", 0x24e1: "VPALIGNR", 0x125a: "CMPORDSD", 0x1b61: "VPXOR",
0xa1: "JBE", 0x46f: "FXAM", 0x10e1: "XSAVEOPT", 0x669: "MUL", 0x19dc: "VPMINUB",
0x1b41: "VPADDSW", 0x1b4a: "PMAXSW", 0x256b: "VINSERTPS", 0x13f6: "VCMPEQPD",
0x5f7: "FFREE", 0x1f17: "VMASKMOVPS", 0x18f0: "CMPXCHG8B", 0x2015: "PMAXSD",
0x1b30: "VPADDSB", 0x10: "PUSH", 0x25d0: "VPCLMULQDQ", 0x1264: "VCMPEQPS",
0x7f0: "PFRSQIT1", 0x2453: "ROUNDPS", 0x2ff: "SETNO", 0x6fb: "XGETBV", 0x1fd1: "PMINSD",
0x1c3a: "PADDB", 0x4ce: "FPREM1", 0x200: "CLD", 0x52c: "FIMUL", 0xc1e: "XORPD",
0x1ec: "CLC", 0x43c: "FSTP", 0x24b2: "BLENDPD", 0x1a05: "PADDUSW", 0x1c96: "FNINIT",
0x319: "SETNZ", 0x1967: "PADDQ", 0xc17: "XORPS", 0x22a0: "VFNMSUB213SS", 0x333: "SETNS",
0x525: "FIADD", 0x340: "SETNP", 0xf59: "VPUNPCKHQDQ", 0xd42: "SUBPS", 0x1246: "CMPNLTSD",
0x684: "LLDT", 0x223f: "VFMSUB213SD", 0x1de3: "PTEST", 0x217a: "VFNMSUB132PD",
0x279: "GETSEC", 0x1d7f: "VPSIGND", 0x1ab: "JCXZ", 0x11f7: "CMPNLTSS", 0x34d: "SETGE",
0x1128: "CMPEQPS", 0x1bca: "PSADBW", 0x272b: "MOVSXD", 0x216c: "VFNMSUB132PS",
0x185: "AAD", 0x2402: "VAESENCLAST", 0xf4d: "PUNPCKHQDQ", 0x88e: "MOVLPD",
0x19fb: "VPADDUSW", 0x12de: "VCMPFALSEPS", 0x180: "AAM", 0xf40: "VPUNPCKLQDQ",
0xd8c: "MINSS", 0x1c58: "PADDD", 0x1470: "VCMPFALSEPD", 0xe54: "VPUNPCKLWD",
0x886: "MOVLPS", 0x73f: "CLGI", 0x4c: "AAS", 0x139: "LODS", 0x2d3: "CMOVNP",
0xd93: "MINSD", 0x1f6: "CLI", 0xa62: "CVTTSD2SI", 0x533: "FICOM", 0x1f2f: "PMOVZXBW",
0xc3c: "ADDPD", 0x770: "PREFETCHW", 0x134f: "VCMPNEQ_USPS", 0xc2d: "VXORPD",
0x1b1d: "POR", 0x16: "POP", 0x2447: "VPERM2F128", 0x19e: "LOOPZ", 0x1ad7: "MOVNTDQ",
0x1dc: "INT1", 0x382: "CMPXCHG", 0x1e0e: "VBROADCASTF128", 0x1525: "VCMPNGE_UQPD",
0x1cd4: "PHADDW", 0xc25: "VXORPS", 0x14e1: "VCMPNEQ_USPD", 0xc35: "ADDPS",
0x812: "PFMUL", 0x6a7: "LGDT", 0x68f: "VERR", 0x695: "VERW", 0x109d: "VHSUBPD",
0x197e: "VPMULLW", 0x85b: "VMOVUPS", 0x174: "INTO", 0x1c8f: "FCLEX", 0x10a6: "VHSUBPS",
0xccb: "CVTSD2SS", 0x48b: "FLDPI", 0x1e2d: "PABSW", 0xe1a: "VMAXPD", 0x1d3: "JMP FAR",
0xecf: "VPACKUSWB", 0x581: "FUCOMPP", 0x864: "VMOVUPD", 0x82c: "PSWAPD", 0x1c49: "PADDW",
0x1b86: "PSLLD", 0x756: "SWAPGS", 0x896: "MOVSLDUP", 0x9df: "CVTSI2SS", 0x17c3: "VCMPTRUESD",
0x11e1: "CMPUNORDSS", 0xd36: "VCVTTPS2DQ", 0xb4d: "SQRTSD", 0x1e00: "VBROADCASTSD",
0x1c1c: "PSUBD", 0xce: "TEST", 0x39a: "LGS", 0x1631: "VCMPTRUESS", 0x266: "SYSENTER",
0x9e9: "CVTSI2SD", 0x175b: "VCMPNLESD", 0x1dbc: "VTESTPD", 0x98: "JZ", 0xde6: "VDIVSS",
0xc10: "VORPD", 0xb3: "JP", 0xaa: "JS", 0xbc: "JL", 0xb82: "RSQRTSS", 0x1db3: "VTESTPS",
0x86: "JO", 0xe12: "VMAXPS", 0x19ae: "PSUBUSB", 0xca: "JG", 0x1df2: "VBROADCASTSS",
0xa6: "JA", 0x8f: "JB", 0xe9: "CWDE", 0x140a: "VCMPLEPD", 0x104e: "VMWRITE",
0x1278: "VCMPLEPS", 0x1999: "PMOVMSKB", 0x2561: "INSERTPS", 0x2614: "PCMPESTRI",
0x273a: "WAIT", 0x1541: "VCMPFALSE_OSPD", 0x25fd: "PCMPESTRM", 0xe60: "PUNPCKLDQ",
0xc7f: "MULSS", 0xd66: "VSUBPD", 0x1177: "CMPEQPD", 0x17a1: "VCMPNEQ_OQSD",
0xb02: "VCOMISD", 0xdaa: "VMINSS", 0x1c5f: "VPADDD", 0x258: "RDMSR", 0x1d6e: "VPSIGNW",
0x1b1: "JECXZ", 0xc86: "MULSD", 0x154: "ENTER", 0x2439: "MOVBE", 0x102c: "VZEROALL",
0x2748: "_3DNOW", 0xdb2: "VMINSD", 0x160f: "VCMPNEQ_OQSS", 0x7fa: "PFSUBR",
0x12f9: "VCMPGEPS", 0x19b7: "VPSUBUSB", 0x2357: "VFMSUB231SD", 0x2037: "PMAXUD",
0x269e: "FXSAVE", 0x590: "FISTTP", 0x148b: "VCMPGEPD", 0x249f: "BLENDPS", 0x172e: "VCMPLESD",
0x5b7: "FCMOVNBE", 0x234a: "VFMSUB231SS", 0x25dc: "VBLENDVPS", 0x25bb: "VMPSADBW",
0x19ca: "VPSUBUSW", 0x1724: "VCMPLTSD", 0x1eed: "MOVNTDQA", 0x18d6: "SHUFPD",
0xd49: "SUBPD", 0xb3d: "SQRTPD", 0x964: "VMOVHPD", 0x6c7: "VMCALL", 0x20d9: "VFMADD132PD",
0x15b: "LEAVE", 0x18ce: "SHUFPS", 0x1319: "VCMPEQ_OSPS", 0x261f: "VPCMPESTRI",
0x1592: "VCMPLTSS", 0x2608: "VPCMPESTRM", 0x20cc: "VFMADD132PS", 0x6ad: "LIDT",
0x4a8: "F2XM1", 0x95b: "VMOVHPS", 0x1f98: "PMOVZXDQ", 0x1020: "VZEROUPPER",
0xb35: "SQRTPS", 0xbeb: "VANDNPS", 0x196e: "VPADDQ", 0x4e8: "FPREM", 0x1c50: "VPADDW",
0x24d8: "PALIGNR", 0x1fc0: "PMINSB", 0xe9f: "PCMPGTW", 0x36c: "SHLD", 0x14f: "LDS",
0x1c41: "VPADDB", 0x719: "VMRUN", 0x26b0: "RDFSBASE", 0xbf4: "VANDNPD", 0x190: "XLAT",
0xd4: "XCHG", 0x4df: "FINCSTP", 0x1990: "MOVDQ2Q", 0x1b0c: "PMINSW", 0x6b3: "SMSW",
0x1d5d: "VPSIGNB", 0x10c7: "XRSTOR", 0x24bb: "VBLENDPD", 0xc0: "JGE", 0x135d: "VCMPNLT_UQPS",
0x1766: "VCMPORDSD", 0x24a8: "VBLENDPS", 0x469: "FTST", 0x1a8e: "CVTTPD2DQ",
0x15d4: "VCMPORDSS", 0x14ef: "VCMPNLT_UQPD", 0x2188: "VFNMSUB132SS", 0x10cf: "XRSTOR64",
0x29: "AND", 0xb8b: "VRSQRTPS", 0x10ff: "CLFLUSH", 0x1cc3: "PSHUFB", 0x442: "FLDENV",
0xda: "MOV", 0xfaa: "PSHUFD", 0xc5: "JLE", 0x5d0: "FEDISI", 0x70b: "VMFUNC",
0xea8: "VPCMPGTW", 0x809: "PFCMPEQ", 0x169d: "VCMPORD_SSS", 0xfa2: "PSHUFW",
0x24f3: "VPEXTRB", 0x1ab9: "VCVTDQ2PD", 0xf79: "VMOVQ", 0x483: "FLDL2E", 0x250c: "VPEXTRD",
0x1d28: "VPHSUBW", 0x2284: "VFNMSUB213PS", 0x21f1: "VFMADD213PD", 0x739: "STGI",
0x4bd: "FPATAN", 0x2515: "VPEXTRQ", 0x437: "FST", 0x168: "INT 3", 0x598: "FIST",
0x271b: "VMCLEAR", 0x1e75: "PMOVSXBQ", 0x42: "AAA", 0x1d39: "VPHSUBD", 0xa41: "CVTTPS2PI",
0x114f: "CMPNEQPS", 0x155f: "VCMPGE_OQPD", 0x1b68: "LDDQU", 0xb79: "RSQRTPS",
0xc59: "VADDPD", 0x7b8: "PFRCP", 0xcc1: "CVTSS2SD", 0x2196: "VFNMSUB132SD",
0x632: "FDIVRP", 0x641: "FBLD", 0x361: "CPUID", 0x251: "RDTSC", 0x24ce: "VPBLENDW",
0xd2b: "VCVTPS2DQ", 0x1b22: "VPOR", 0xc51: "VADDPS", 0x77b: "PI2FW", 0xd7e: "MINPS",
0x17cf: "VCMPEQ_OSSD", 0x1bad: "VPMULUDQ", 0xe0b: "MAXSD", 0x2050: "VPMULLD",
0x558: "FIDIVR", 0xad5: "VUCOMISS", 0x8a0: "MOVDDUP", 0x1ccb: "VPSHUFB", 0x1d42: "PHSUBSW",
0x264d: "VPCMPISTRI", 0xe04: "MAXSS", 0x1a35: "VPAVGB", 0x16d3: "VCMPFALSE_OSSS",
0xd85: "MINPD", 0x4ef: "FYL2XP1", 0xadf: "VUCOMISD", 0x23aa: "VFNMSUB231PD",
0x1849: "VCMPNGE_UQSD", 0xc4a: "ADDSD", 0x6e3: "VMXOFF", 0x1958: "PSRLQ", 0x128f: "VCMPNEQPS",
0x193a: "PSRLW", 0x1a4c: "PSRAD", 0x6a1: "SIDT", 0xe77: "PACKSSWB", 0x10af: "XSAVE",
0x1421: "VCMPNEQPD", 0xfa: "CDQ", 0xc43: "ADDSS", 0x16b7: "VCMPNGE_UQSS", 0x2440: "CRC32",
0x23dc: "VAESIMC", 0x2004: "PMAXSB", 0x2529: "VEXTRACTPS", 0x1813: "VCMPNLT_UQSD",
0x1c05: "VPSUBB", 0x1f8d: "VPMOVZXWQ", 0x13bf: "VCMPNEQ_OSPS", 0xa1b: "MOVNTSS",
0x2542: "VEXTRACTF128", 0x1b28: "PADDSB", 0x75: "IMUL", 0x3d6: "RCR", 0x14d2: "VCMPUNORD_SPD",
0x3d1: "RCL", 0xa24: "MOVNTSD", 0x1551: "VCMPNEQ_OSPD", 0x1681: "VCMPNLT_UQSS",
0xd57: "SUBSD", 0x13f: "SCAS", 0x25c5: "PCLMULQDQ", 0x7bf: "PFRSQRT", 0x2576: "PINSRD",
0x623: "FSUBRP", 0x5b: "PUSHA", 0x1a16: "VPMAXUB", 0x1143: "CMPUNORDPS", 0x203f: "VPMAXUD",
0x463: "FABS", 0x1e7f: "VPMOVSXBQ", 0x149f: "VCMPTRUEPD", 0x23e: "FEMMS", 0x163d: "VCMPEQ_OSSS",
0x220b: "VFMADD213SD", 0x1e6a: "VPMOVSXBD", 0x1192: "CMPUNORDPD", 0x1907: "VMPTRST",
0x18fb: "CMPXCHG16B", 0x130d: "VCMPTRUEPS", 0x12d3: "VCMPNGTPS", 0x1c87: "FNCLEX",
0x123c: "CMPNEQSD", 0x1771: "VCMPEQ_UQSD", 0x579: "FCMOVU", 0x103e: "EXTRQ",
0x25a5: "DPPD", 0x2e2: "CMOVGE", 0x2550: "PINSRB", 0x15df: "VCMPEQ_UQSS", 0x1d14: "VPMADDUBSW",
0x11ed: "CMPNEQSS", 0x2309: "VFMADD231PD", 0x519: "FSIN", 0x1bf: "IN", 0x568: "FCMOVE",
0x44a: "FLDCW", 0x2598: "DPPS", 0x560: "FCMOVB", 0x1941: "VPSRLW", 0x10bf: "LFENCE",
0xaa3: "CVTSD2SI", 0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x195f: "VPSRLQ", 0x614: "FMULP",
0x9c2: "VMOVAPD", 0x1657: "VCMPLE_OQSS", 0x2c4: "CMOVNS", 0x5ae: "FCMOVNE",
0x288: "CMOVNO", 0x1a85: "VPMULHW", 0x1950: "VPSRLD", 0x1061: "CVTPS2PH", 0xa85: "CVTPS2PI",
0x1ce5: "PHADDD", 0xcad: "CVTPS2PD", 0x1e34: "VPABSW", 0x17e9: "VCMPLE_OQSD",
0x9b9: "VMOVAPS", 0x1c14: "VPSUBW", 0x823: "PMULHRW", 0x9a9: "MOVAPS", 0x7b1: "PFMIN",
0xf66: "MOVD", 0x937: "MOVHPS", 0xc71: "MULPS", 0x126e: "VCMPLTPS", 0x368: "BT",
0x9b1: "MOVAPD", 0x1393: "VCMPNGE_UQPS", 0x1b8: "JRCXZ", 0xc78: "MULPD", 0x127: "MOVS",
0x6bf: "INVLPG", 0xf6c: "MOVQ", 0xda2: "VMINPD", 0x1e3c: "PABSD", 0x11b: "SAHF",
0x13e7: "VCMPTRUE_USPS", 0x782: "PI2FD", 0x1e1e: "PABSB", 0x2495: "VROUNDSD",
0x1a26: "VPANDN", 0xe6b: "VPUNPCKLDQ", 0x63a: "FDIVP", 0x1c2b: "PSUBQ", 0x42b: "FDIVR",
0x425: "FDIV", 0x1579: "VCMPTRUE_USPD", 0x766: "PREFETCH", 0x101a: "EMMS",
0xd9a: "VMINPS", 0x22fc: "VFMADD231PS", 0x2292: "VFNMSUB213PD", 0xa99: "CVTSS2SI",
0x93f: "MOVHPD", 0x29f: "CMOVZ", 0x1a62: "VPAVGW", 0xff: "CQO", 0x1c23: "VPSUBD",
0x2cc: "CMOVP", 0x1588: "VCMPEQSS", 0x2bd: "CMOVS", 0x1e60: "PMOVSXBD", 0x2482: "VROUNDSS",
0x1c32: "VPSUBQ", 0x2db: "CMOVL", 0x191a: "ADDSUBPS", 0x281: "CMOVO", 0x2b6: "CMOVA",
0x290: "CMOVB", 0xeda: "PUNPCKHBW", 0x2642: "PCMPISTRI", 0x2f2: "CMOVG", 0x19a3: "VPMOVMSKB",
0x2420: "AESDECLAST", 0x845: "MOVUPD", 0x20bc: "VFMSUBADD132PD", 0x1bd2: "VPSADBW",
0x3f7: "XBEGIN", 0x246f: "VROUNDPD", 0x6b9: "LMSW", 0x2072: "INVEPT", 0x39f: "MOVZX",
0xbbd: "ANDPS", 0x20ac: "VFMSUBADD132PS", 0x83d: "MOVUPS", 0x1627: "VCMPGTSS",
0x1a6a: "PMULHUW", 0x25ab: "VDPPD", 0x24fc: "PEXTRD", 0x1602: "VCMPFALSESS",
0x26ce: "RDGSBASE", 0x1b: "OR", 0x18c5: "VPEXTRW", 0x1af2: "VPSUBSB", 0x26ba: "FXRSTOR",
0x21d: "CLTS", 0x1857: "VCMPNGT_UQSD", 0x15f7: "VCMPNGTSS", 0x5ef: "FRSTOR",
0x1794: "VCMPFALSESD", 0x49a: "FLDLN2", 0x2535: "VINSERTF128", 0x1b03: "VPSUBSW",
0x1ba4: "PMULUDQ", 0x56: "DEC", 0x13af: "VCMPFALSE_OSPS", 0x432: "FLD", 0x1fa2: "VPMOVZXDQ",
0x2479: "ROUNDSS", 0x9f3: "VCVTSI2SS", 0x18bd: "PEXTRW", 0x26a6: "FXSAVE64",
0x3c7: "ROL", 0x20f3: "VFMADD132SD", 0x1189: "CMPLEPD", 0xcf6: "VCVTSD2SS",
0x605: "FUCOMP", 0x1ce: "JMP", 0x171a: "VCMPEQSD", 0xd01: "CVTDQ2PS", 0x16fe: "VCMPGT_OQSS",
0x5e0: "FUCOMI", 0x1121: "LZCNT", 0xbad: "VRCPPS", 0x1a0e: "PMAXUB", 0x1ced: "VPHADDD",
0x9fe: "VCVTSI2SD", 0x1890: "VCMPGT_OQSD", 0x3cc: "ROR", 0x22b: "INVD", 0xab8: "VCVTSD2SI",
0x240f: "AESDEC", 0x1250: "CMPNLESD", 0x354: "SETLE", 0x22dc: "VFMSUBADD231PS",
0x2364: "VFNMADD231PS", 0x10b6: "XSAVE64", 0xef1: "PUNPCKHWD", 0x1e94: "VPMOVSXWD",
0xcb7: "CVTPD2PS", 0x8a9: "VMOVHLPS", 0x22ec: "VFMSUBADD231PD", 0xa8f: "CVTPD2PI",
0x1201: "CMPNLESS", 0x1ec9: "PMULDQ", 0x1ea9: "VPMOVSXWQ", 0x1750: "VCMPNLTSD",
0x2100: "VFMSUB132PS", 0x2372: "VFNMADD231PD", 0x1cbc: "FSTSW", 0x75e: "RDTSCP",
0x10d9: "MFENCE", 0x20e6: "VFMADD132SS", 0x1ff3: "PMINUD", 0x5ca: "FENI", 0x68: "BOUND",
0x245c: "VROUNDPS", 0xfbb: "PSHUFLW", 0xc9d: "VMULSS", 0x1865: "VCMPFALSE_OSSD",
0xd20: "VCVTDQ2PS", 0x159c: "VCMPLESS", 0x457: "FNOP", 0x1159: "CMPNLTPS",
0x129a: "VCMPNLTPS", 0x492: "FLDLG2", 0x223: "SYSRET", 0x1c80: "FSTCW", 0x2232: "VFMSUB213SS",
0x745: "SKINIT", 0xbd3: "VANDPD", 0x4a2: "FLDZ", 0x33: "SUB", 0x1cdc: "VPHADDW",
0x664: "NEG", 0x1fe2: "PMINUW", 0xdfd: "MAXPD", 0x1379: "VCMPORD_SPS", 0x133: "STOS",
0x23c6: "VFNMSUB231SD", 0x1738: "VCMPUNORDSD", 0x834: "PAVGUSB", 0x150b: "VCMPORD_SPD",
0xdf6: "MAXPS", 0x19d4: "PMINUB", 0x1bf1: "VMASKMOVDQU", 0x647: "FBSTP", 0x18ac: "PINSRW",
0x1f78: "VPMOVZXWD", 0x1fea: "VPMINUW", 0x1821: "VCMPNLE_UQSD", 0x18a: "SALC",
0x24eb: "PEXTRB", 0x8ee: "VUNPCKLPS", 0x168f: "VCMPNLE_UQSS", 0xf80: "MOVDQA",
0x15be: "VCMPNLTSS", 0x1b95: "PSLLQ", 0xa2d: "VMOVNTPS", 0x1ffb: "VPMINUD",
0x978: "PREFETCHNTA", 0x8f9: "VUNPCKLPD", 0x1057: "CVTPH2PS", 0x266a: "VAESKEYGENASSIST",
0x1afb: "PSUBSW", 0x177e: "VCMPNGESD", 0x1c67: "FNSTENV", 0x1cb4: "FNSTSW",
0x119e: "CMPNEQPD", 0x1a5b: "PAVGW", 0xa12: "MOVNTPD", 0x1518: "VCMPEQ_USPD",
0x5d8: "FSETPM", 0x1dcf: "BLENDVPS", 0x21b4: "VFMADDSUB213PD", 0xb: "ADD",
0x15ec: "VCMPNGESS", 0x1f: "ADC", 0x1aea: "PSUBSB", 0x1dd9: "BLENDVPD", 0xee5: "VPUNPCKHBW",
0x25f: "RDPMC", 0xa09: "MOVNTPS", 0x1110: "BSF", 0x1400: "VCMPLTPD", 0x1a2e: "PAVGB",
0xdf: "LEA", 0x1aad: "VCVTTPD2DQ", 0xe95: "VPCMPGTB", 0xebb: "VPCMPGTD", 0x475: "FLD1",
0x1bc0: "VPMADDWD", 0x17f6: "VCMPUNORD_SSD", 0x14a: "LES", 0x313: "SETZ", 0x1fb6: "VPCMPGTQ",
0xca5: "VMULSD", 0x21e4: "VFMADD213PS", 0x15c9: "VCMPNLESS", 0x87d: "MOVHLPS",
0x2065: "VPHMINPOSUW", 0x1e43: "VPABSD", 0x1a3d: "PSRAW", 0x7cf: "PFADD", 0x209c: "VFMADDSUB132PD",
0xaf1: "COMISD", 0x13cd: "VCMPGE_OQPS", 0xe22: "VMAXSS", 0x1230: "CMPUNORDSD",
0x4ff: "FSINCOS", 0xae9: "COMISS", 0x208c: "VFMADDSUB132PS", 0xb9f: "RCPPS",
0x2142: "VFNMADD132PD", 0x451: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcd5: "VCVTPS2PD",
0x1bb7: "PMADDWD", 0xbc4: "ANDPD", 0x1333: "VCMPLE_OQPS", 0x1789: "VCMPNGTSD",
0x239c: "VFNMSUB231PS", 0x64e: "FUCOMIP", 0xc8d: "VMULPS", 0x2134: "VFNMADD132PS",
0x26e1: "WRFSBASE", 0x38: "DAS", 0x14c5: "VCMPLE_OQPD", 0x17a: "IRET", 0x3c0: "BSWAP",
0xe32: "PUNPCKLBW", 0x2026: "PMAXUW", 0x2636: "VPCMPISTRM", 0x1b77: "PSLLW",
0x1664: "VCMPUNORD_SSS", 0x224c: "VFNMADD213PS", 0xa79: "VCVTTSD2SI", 0x233d: "VFMSUB231PD",
0x13a1: "VCMPNGT_UQPS", 0x1c78: "FNSTCW", 0x248c: "ROUNDSD", 0x11b2: "CMPNLEPD",
0x2504: "PEXTRQ", 0x1a7d: "PMULHW", 0x1cff: "VPHADDSW", 0x59e: "FISTP", 0x1f83: "PMOVZXWQ",
0xce0: "VCVTPD2PS", 0x170b: "VCMPTRUE_USSS", 0xc69: "VADDSD", 0x1dc5: "PBLENDVB",
0x6d9: "VMRESUME", 0xacc: "UCOMISD", 0x1f6e: "PMOVZXWD", 0xa4c: "CVTTPD2PI",
0xac3: "UCOMISS", 0xe81: "VPACKSSWB", 0xc61: "VADDSS", 0xfb2: "PSHUFHW", 0x189d: "VCMPTRUE_USSD",
0x6f4: "MWAIT"
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
                asm += b" " + di.operands.p
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
        print ("Bad meta-flags: {}".format(realvalue))
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
