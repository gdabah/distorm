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

#==============================================================================
# Load the diStorm DLL

# Guess the DLL filename and load the library.
_distorm_path = split(__file__)[0]
potential_libs = ['distorm3.dll', 'libdistorm3.dll', 'libdistorm3.so', 'libdistorm3.dylib']
lib_was_found = False
for i in potential_libs:
    try:
        _distorm_file = join(_distorm_path, i)
        _distorm = cdll.LoadLibrary(_distorm_file)
        lib_was_found = True
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
        ('usedRegistersMask', c_uint16), # used registers mask.
        ('opcode', c_uint16),  # look up in opcode table
        ('ops', _Operand*4),
        ('size', c_ubyte),
        ('segment', c_ubyte), # -1 if unused. See C headers for more info
        ('base', c_ubyte),    # base register for indirections
        ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
        ('dispSize', c_ubyte),
        ('meta', c_ubyte) # meta flags - instruction set class, etc. See C headers again...
    ]


#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType)

Mnemonics = {0x66e: "SLDT", 0x62: "POPA", 0x8eb: "UNPCKHPS", 0x115: "POPF", 0x11bc: "CMPLTSS",
0x85c: "VMOVSD", 0x786: "PFPNACC", 0xb11: "VMOVMSKPD", 0x734: "INVLPGA", 0x8f5: "UNPCKHPD",
0x270: "SYSEXIT", 0x7af: "PFSUB", 0x120b: "CMPLTSD", 0x1a60: "VPMULHUW", 0x1d38: "VPHSUBSW",
0x12b5: "VCMPNGEPS", 0x854: "VMOVSS", 0x6f: "ARPL", 0x52f: "FICOMP", 0x162: "RETF",
0x452: "FCHS", 0x1127: "CMPLEPS", 0xeef: "PUNPCKHDQ", 0x23fb: "VAESDEC", 0x5f3: "FUCOM",
0x129d: "VCMPORDPS", 0x19ae: "PSUBUSW", 0x1b48: "PXOR", 0x1e12: "VPABSB", 0x24a: "WRMSR",
0x12a8: "VCMPEQ_UQPS", 0x22b0: "VFMADDSUB231PD", 0x7c6: "PFMAX", 0x16d0: "VCMPNEQ_OSSS",
0x223e: "VFNMADD213PD", 0x3bd: "MOVNTI", 0x7bd: "PFCMPGT", 0x2364: "VFNMADD231SS",
0x244a: "ROUNDPD", 0x12f0: "VCMPGTPS", 0xb9c: "VRCPSS", 0x2134: "VFNMADD132SS",
0x1447: "VCMPNGEPD", 0x2209: "VFMSUB213PD", 0x1862: "VCMPNEQ_OSSD", 0x2670: "VPSLLDQ",
0x78f: "PFCMPGE", 0x1482: "VCMPGTPD", 0x1a86: "CVTDQ2PD", 0x1214: "CMPLESD",
0xae: "JNS", 0xdd5: "VDIVSD", 0xb7: "JNP", 0x24f9: "EXTRACTPS", 0x1f46: "PMOVZXBQ",
0x9c: "JNZ", 0x5dd: "FCOMI", 0xee3: "VPUNPCKHWD", 0x1f31: "PMOVZXBD", 0x1acd: "VMOVNTDQ",
0x1e77: "PMOVSXWD", 0x1101: "POPCNT", 0x8a: "JNO", 0x1c92: "FNSAVE", 0x1a5: "LOOP",
0xb06: "VMOVMSKPS", 0x470: "FLDL2T", 0x12d: "CMPS", 0x40d: "FSUB", 0xda1: "DIVPS",
0x1d1e: "PHSUBD", 0x11b3: "CMPEQSS", 0x1e7: "CMC", 0xcfc: "CVTTPS2DQ", 0xda8: "DIVPD",
0xf59: "VMOVD", 0x104: "CALL FAR", 0x1d75: "PMULHRSW", 0x1d7f: "VPMULHRSW",
0x1d0d: "PHSUBW", 0x1202: "CMPEQSD", 0x3b7: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x1057: "VHADDPS", 0x2067: "INVVPID", 0x20f: "LSL", 0x1660: "VCMPNEQ_USSS",
0x104e: "VHADDPD", 0x38b: "LSS", 0x20f1: "VFMSUB132PD", 0x121: "LAHF", 0x7e9: "PFACC",
0x800: "PFRCPIT2", 0xe24: "VPUNPCKLBW", 0x7cd: "PFRCPIT1", 0x1f9a: "PCMPGTQ",
0x4a4: "FYL2X", 0x181c: "VCMPORD_SSD", 0x1936: "PSRLD", 0x10f0: "SFENCE", 0xcf2: "CVTPS2DQ",
0x24a9: "PBLENDW", 0x21a8: "VFMSUBADD213PS", 0xe73: "PCMPGTB", 0xe99: "PCMPGTD",
0x23d1: "VAESENC", 0x954: "VMOVSHDUP", 0x258d: "MPSADBW", 0x14ea: "VCMPNLE_UQPD",
0x707: "VMMCALL", 0x102c: "INSERTQ", 0x224c: "VFNMADD213SS", 0x9bc: "CVTPI2PD",
0x16f: "INT", 0x1d8a: "VPERMILPS", 0x1e2: "HLT", 0x2046: "PHMINPOSUW", 0x5b6: "FCMOVNU",
0x7b: "INS", 0x64c: "FCOMIP", 0x9b2: "CVTPI2PS", 0x225a: "VFNMADD213SD", 0xeac: "PACKUSWB",
0xe4: "CBW", 0x718: "VMSAVE", 0x10e: "PUSHF", 0x654: "NOT", 0x59a: "FCMOVNB",
0x245: "NOP", 0x4ed: "FSQRT", 0x1d95: "VPERMILPD", 0x51: "INC", 0x239: "UD2",
0xfe4: "VPCMPEQW", 0x2606: "PCMPISTRM", 0x1ed0: "VPCMPEQQ", 0x1150: "CMPNLEPS",
0x1829: "VCMPEQ_USSD", 0x1401: "VCMPUNORDPD", 0x602: "FADDP", 0x145: "RET",
0xff7: "VPCMPEQD", 0x1fc6: "VPMINSD", 0x2533: "VPINSRB", 0xfd1: "VPCMPEQB",
0x18fd: "ADDSUBPD", 0x108a: "FXSAVE64", 0x1697: "VCMPEQ_USSS", 0x1d53: "PSIGNW",
0x1eab: "VPMOVSXDQ", 0x200a: "VPMAXSD", 0x35b: "SETG", 0x1ff9: "VPMAXSB", 0x327: "SETA",
0x306: "SETB", 0x268c: "STMXCSR", 0x347: "SETL", 0x20e4: "VFMSUB132PS", 0x2f9: "SETO",
0xbca: "ANDNPD", 0x1109: "BSR", 0x8b7: "VMOVDDUP", 0x1b3f: "VPMAXSW", 0x1d64: "PSIGND",
0x33a: "SETP", 0x1d42: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x1593: "VCMPUNORDSS",
0x3ab: "BSF", 0x26b1: "VMXON", 0xbb2: "VANDPS", 0x6f8: "XSETBV", 0x1c3: "OUT",
0x67f: "LTR", 0x2561: "VPINSRD", 0xa54: "VCVTTSS2SI", 0x265f: "VPSRLDQ", 0x4cb: "FDECSTP",
0x2657: "PSRLDQ", 0x1870: "VCMPGE_OQSD", 0x2668: "PSLLDQ", 0x514: "FCOS", 0x4ba: "FXTRACT",
0x16de: "VCMPGE_OQSS", 0x1ee4: "VMOVNTDQA", 0x1520: "VCMPNGT_UQPD", 0x3fa: "FMUL",
0x13c7: "VCMPGT_OQPS", 0x610: "FCOMPP", 0x777: "PF2ID", 0xf5: "CWD", 0x132d: "VCMPUNORD_SPS",
0x2ea: "CMOVLE", 0xfb4: "VPSHUFHW", 0x1559: "VCMPGT_OQPD", 0x1ce3: "PHADDSW",
0x770: "PF2IW", 0xa1e: "VMOVNTPD", 0x406: "FCOMP", 0x8c1: "UNPCKLPS", 0x1bd2: "MASKMOVDQU",
0x565: "FCMOVBE", 0x14a5: "VCMPLT_OQPD", 0xe11: "VMAXSD", 0x1419: "VCMPNLTPD",
0x984: "PREFETCHT2", 0x978: "PREFETCHT1", 0x96c: "PREFETCHT0", 0x8cb: "UNPCKLPD",
0xa3e: "CVTTSS2SI", 0x663: "DIV", 0x1ea1: "PMOVSXDQ", 0x160a: "VCMPGESS", 0xef: "CDQE",
0x2695: "VSTMXCSR", 0x53e: "FISUBR", 0x1fb5: "VPMINSB", 0x21fc: "VFMSUB213PS",
0x1313: "VCMPLT_OQPS", 0x11c5: "CMPLESS", 0x1b01: "VPMINSW", 0x1c5d: "FSTENV",
0x179c: "VCMPGESD", 0x1dd7: "VPTEST", 0x537: "FISUB", 0x205: "STD", 0xf10: "VPACKSSDW",
0x3d: "XOR", 0xc7c: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x2679: "LDMXCSR",
0x116d: "CMPLTPD", 0xbe4: "ORPS", 0x1ef9: "VPACKUSDW", 0x620: "FSUBP", 0x674: "STR",
0x413: "FSUBR", 0x111e: "CMPLTPS", 0x2307: "VFMADD231SD", 0x26c6: "PAUSE",
0x1a90: "CVTPD2DQ", 0x372: "RSM", 0xb57: "VSQRTSD", 0xbf0: "VORPS", 0x2188: "VFMADDSUB213PS",
0x109d: "FXRSTOR64", 0x143a: "VCMPEQ_UQPD", 0x8ff: "VUNPCKHPS", 0x1cf6: "PMADDUBSW",
0x1358: "VCMPNLE_UQPS", 0x1b6b: "VPSLLW", 0x1bc8: "MASKMOVQ", 0x1c8: "CALL",
0xb4e: "VSQRTSS", 0x19df: "PADDUSB", 0x101d: "VMREAD", 0x10e4: "XSAVEOPT64",
0x90a: "VUNPCKHPD", 0xd45: "VSUBPS", 0xcd2: "VCVTSS2SD", 0x2410: "VAESDECLAST",
0x1068: "HSUBPS", 0xa94: "VCVTSS2SI", 0x25cd: "VPBLENDVB", 0x17a6: "VCMPGTSD",
0x57f: "FILD", 0xae0: "VCOMISS", 0x1060: "HSUBPD", 0x239c: "VFNMSUB231SS",
0x1a40: "VPSRAD", 0x1292: "VCMPNLEPS", 0x3ea: "SAL", 0x214: "SYSCALL", 0xb7c: "VRSQRTSS",
0x256a: "VPINSRQ", 0xfab: "VPSHUFD", 0x1e38: "PMOVSXBW", 0x1a31: "VPSRAW",
0x1424: "VCMPNLEPD", 0x3f4: "FADD", 0x3ef: "SAR", 0x1abc: "MOVNTQ", 0x2634: "AESKEYGENASSIST",
0xf06: "PACKSSDW", 0x21e2: "VFMADD213SS", 0xf77: "VMOVDQA", 0x8ac: "VMOVSLDUP",
0x4fd: "FRNDINT", 0x1963: "PMULLW", 0xdb6: "DIVSD", 0xaf2: "MOVMSKPS", 0x201b: "VPMAXUW",
0xdc5: "VDIVPD", 0x1e42: "VPMOVSXBW", 0x1e8c: "PMOVSXWQ", 0x2035: "PMULLD",
0xf80: "VMOVDQU", 0x2292: "VFNMSUB213SD", 0x297: "CMOVAE", 0x1498: "VCMPEQ_OSPD",
0xdbd: "VDIVPS", 0x93: "JAE", 0xafc: "MOVMSKPD", 0xdaf: "DIVSS", 0x1c9a: "FSAVE",
0x1ec7: "PCMPEQQ", 0xfbe: "VPSHUFLW", 0xfdb: "PCMPEQW", 0x2682: "VLDMXCSR",
0x20fe: "VFMSUB132SS", 0x11a9: "CMPORDPD", 0xb8d: "RCPSS", 0x1b7a: "VPSLLD",
0x668: "IDIV", 0x142f: "VCMPORDPD", 0xfc8: "PCMPEQB", 0xfee: "PCMPEQD", 0x1b89: "VPSLLQ",
0x1f50: "VPMOVZXBQ", 0x21b8: "VFMSUBADD213PD", 0x25c2: "VBLENDVPD", 0x115a: "CMPORDPS",
0xf1b: "PUNPCKLQDQ", 0x19d8: "VPAND", 0x146a: "VCMPNEQ_OQPD", 0x103e: "HADDPD",
0x191c: "VADDSUBPS", 0x18d4: "VSHUFPD", 0x22a0: "VFMADDSUB231PS", 0xd5d: "VSUBSD",
0xb3c: "VSQRTPS", 0x92e: "MOVSHDUP", 0x2372: "VFNMADD231SD", 0x6c4: "VMLAUNCH",
0x1f10: "VMASKMOVPD", 0x1046: "HADDPS", 0x12d8: "VCMPNEQ_OQPS", 0xe30: "PUNPCKLWD",
0x16b2: "VCMPNGT_UQSS", 0xb45: "VSQRTPD", 0xd55: "VSUBSS", 0x18cb: "VSHUFPS",
0x15a0: "VCMPNEQSS", 0x1b5c: "VLDDQU", 0x1637: "VCMPLT_OQSS", 0x1b26: "PADDSW",
0x1373: "VCMPEQ_USPS", 0xbea: "ORPD", 0x1a0c: "PANDN", 0x4ab: "FPTAN", 0x546: "FIDIV",
0x17c9: "VCMPLT_OQSD", 0x269f: "VMPTRLD", 0x2314: "VFMSUB231PS", 0x1732: "VCMPNEQSD",
0x1ebe: "VPMULDQ", 0x196: "LOOPNZ", 0x126f: "VCMPUNORDPS", 0x3e5: "SHR", 0x37c: "SHRD",
0x6e0: "MONITOR", 0x23da: "AESENCLAST", 0x83b: "MOVSD", 0x18a1: "VPINSRW",
0x710: "VMLOAD", 0x915: "MOVLHPS", 0x8a3: "VMOVLPD", 0x1974: "MOVQ2DQ", 0xb2c: "SQRTSS",
0x2579: "VDPPS", 0xd37: "SUBSS", 0x3b0: "MOVSX", 0x938: "VMOVLHPS", 0x89a: "VMOVLPS",
0xefa: "VPUNPCKHDQ", 0x1ab1: "VCVTPD2DQ", 0x3e0: "SHL", 0x834: "MOVSS", 0x2559: "PINSRQ",
0x77e: "PFNACC", 0xf6f: "MOVDQU", 0x80: "OUTS", 0x1beb: "PSUBB", 0x377: "BTS",
0x390: "BTR", 0x17f2: "VCMPNEQ_USSD", 0x690: "SGDT", 0x22fa: "VFMADD231SS",
0x506: "FSCALE", 0x1bfa: "PSUBW", 0x1195: "CMPNLTPD", 0x1eef: "PACKUSDW", 0x20a: "LAR",
0x3a6: "BTC", 0x2142: "VFNMADD132SD", 0x1452: "VCMPNGTPD", 0x1f26: "VPMOVZXBW",
0x210b: "VFMSUB132SD", 0x23b8: "AESIMC", 0x400: "FCOM", 0x1f3b: "VPMOVZXBD",
0x1911: "VADDSUBPD", 0x1c8b: "FINIT", 0x11f8: "CMPORDSS", 0x231: "WBINVD",
0x19d2: "PAND", 0x24c5: "VPALIGNR", 0x1247: "CMPORDSD", 0x1b4e: "VPXOR", 0xa1: "JBE",
0x464: "FXAM", 0x10da: "XSAVEOPT", 0x65e: "MUL", 0x19c9: "VPMINUB", 0x1b2e: "VPADDSW",
0x1b37: "PMAXSW", 0x2546: "VINSERTPS", 0x13e3: "VCMPEQPD", 0x5ec: "FFREE",
0x1f04: "VMASKMOVPS", 0x18dd: "CMPXCHG8B", 0x2002: "PMAXSD", 0x1b1d: "VPADDSB",
0x10: "PUSH", 0x25ab: "VPCLMULQDQ", 0x1251: "VCMPEQPS", 0x7d7: "PFRSQIT1",
0x2437: "ROUNDPS", 0x2ff: "SETNO", 0x6f0: "XGETBV", 0x1fbe: "PMINSD", 0x1c27: "PADDB",
0x4c3: "FPREM1", 0x200: "CLD", 0x521: "FIMUL", 0xc05: "XORPD", 0x1ec: "CLC",
0x431: "FSTP", 0x2496: "BLENDPD", 0x19f2: "PADDUSW", 0x1c83: "FNINIT", 0x319: "SETNZ",
0x1954: "PADDQ", 0xbfe: "XORPS", 0x2284: "VFNMSUB213SS", 0x333: "SETNS", 0x51a: "FIADD",
0x340: "SETNP", 0xf40: "VPUNPCKHQDQ", 0xd29: "SUBPS", 0x1233: "CMPNLTSD", 0x679: "LLDT",
0x2223: "VFMSUB213SD", 0x1dd0: "PTEST", 0x215e: "VFNMSUB132PD", 0x279: "GETSEC",
0x1d6c: "VPSIGND", 0x1ab: "JCXZ", 0x11e4: "CMPNLTSS", 0x34d: "SETGE", 0x1115: "CMPEQPS",
0x1bb7: "PSADBW", 0x26be: "MOVSXD", 0x2150: "VFNMSUB132PS", 0x185: "AAD", 0x23e6: "VAESENCLAST",
0xf34: "PUNPCKHQDQ", 0x875: "MOVLPD", 0x19e8: "VPADDUSW", 0x12cb: "VCMPFALSEPS",
0x180: "AAM", 0xf27: "VPUNPCKLQDQ", 0xd73: "MINSS", 0x1c45: "PADDD", 0x145d: "VCMPFALSEPD",
0xe3b: "VPUNPCKLWD", 0x86d: "MOVLPS", 0x726: "CLGI", 0x4c: "AAS", 0x139: "LODS",
0x2d3: "CMOVNP", 0xd7a: "MINSD", 0x1f6: "CLI", 0xa49: "CVTTSD2SI", 0x528: "FICOM",
0x1f1c: "PMOVZXBW", 0xc23: "ADDPD", 0x757: "PREFETCHW", 0x133c: "VCMPNEQ_USPS",
0xc14: "VXORPD", 0x1b0a: "POR", 0x16: "POP", 0x242b: "VPERM2F128", 0x19e: "LOOPZ",
0x1ac4: "MOVNTDQ", 0x1dc: "INT1", 0x382: "CMPXCHG", 0x1dfb: "VBROADCASTF128",
0x1512: "VCMPNGE_UQPD", 0x1cc1: "PHADDW", 0xc0c: "VXORPS", 0x14ce: "VCMPNEQ_USPD",
0xc1c: "ADDPS", 0x7f9: "PFMUL", 0x69c: "LGDT", 0x684: "VERR", 0x68a: "VERW",
0x1070: "VHSUBPD", 0x196b: "VPMULLW", 0x842: "VMOVUPS", 0x174: "INTO", 0x1c7c: "FCLEX",
0x1079: "VHSUBPS", 0xcb2: "CVTSD2SS", 0x480: "FLDPI", 0x1e1a: "PABSW", 0xe01: "VMAXPD",
0x1d3: "JMP FAR", 0xeb6: "VPACKUSWB", 0x576: "FUCOMPP", 0x84b: "VMOVUPD", 0x813: "PSWAPD",
0x1c36: "PADDW", 0x1b73: "PSLLD", 0x73d: "SWAPGS", 0x87d: "MOVSLDUP", 0x9c6: "CVTSI2SS",
0x17b0: "VCMPTRUESD", 0x11ce: "CMPUNORDSS", 0xd1d: "VCVTTPS2DQ", 0xb34: "SQRTSD",
0x1ded: "VBROADCASTSD", 0x1c09: "PSUBD", 0xce: "TEST", 0x39a: "LGS", 0x161e: "VCMPTRUESS",
0x266: "SYSENTER", 0x9d0: "CVTSI2SD", 0x1748: "VCMPNLESD", 0x1da9: "VTESTPD",
0x98: "JZ", 0xdcd: "VDIVSS", 0xbf7: "VORPD", 0xb3: "JP", 0xaa: "JS", 0xbc: "JL",
0xb69: "RSQRTSS", 0x1da0: "VTESTPS", 0x86: "JO", 0xdf9: "VMAXPS", 0x199b: "PSUBUSB",
0xca: "JG", 0x1ddf: "VBROADCASTSS", 0xa6: "JA", 0x8f: "JB", 0xe9: "CWDE", 0x13f7: "VCMPLEPD",
0x1035: "VMWRITE", 0x1265: "VCMPLEPS", 0x1986: "PMOVMSKB", 0x253c: "INSERTPS",
0x25ef: "PCMPESTRI", 0x26b8: "WAIT", 0x152e: "VCMPFALSE_OSPD", 0x25d8: "PCMPESTRM",
0xe47: "PUNPCKLDQ", 0xc66: "MULSS", 0xd4d: "VSUBPD", 0x1164: "CMPEQPD", 0x178e: "VCMPNEQ_OQSD",
0xae9: "VCOMISD", 0xd91: "VMINSS", 0x1c4c: "VPADDD", 0x258: "RDMSR", 0x1d5b: "VPSIGNW",
0x1b1: "JECXZ", 0xc6d: "MULSD", 0x154: "ENTER", 0x241d: "MOVBE", 0x1013: "VZEROALL",
0xd99: "VMINSD", 0x15fc: "VCMPNEQ_OQSS", 0x7e1: "PFSUBR", 0x12e6: "VCMPGEPS",
0x19a4: "VPSUBUSB", 0x233b: "VFMSUB231SD", 0x2024: "PMAXUD", 0x1082: "FXSAVE",
0x585: "FISTTP", 0x1478: "VCMPGEPD", 0x2483: "BLENDPS", 0x171b: "VCMPLESD",
0x5ac: "FCMOVNBE", 0x232e: "VFMSUB231SS", 0x25b7: "VBLENDVPS", 0x2596: "VMPSADBW",
0x19b7: "VPSUBUSW", 0x1711: "VCMPLTSD", 0x1eda: "MOVNTDQA", 0x18c3: "SHUFPD",
0xd30: "SUBPD", 0xb24: "SQRTPD", 0x94b: "VMOVHPD", 0x6bc: "VMCALL", 0x20bd: "VFMADD132PD",
0x15b: "LEAVE", 0x18bb: "SHUFPS", 0x1306: "VCMPEQ_OSPS", 0x25fa: "VPCMPESTRI",
0x157f: "VCMPLTSS", 0x25e3: "VPCMPESTRM", 0x20b0: "VFMADD132PS", 0x6a2: "LIDT",
0x49d: "F2XM1", 0x942: "VMOVHPS", 0x1f85: "PMOVZXDQ", 0x1007: "VZEROUPPER",
0xb1c: "SQRTPS", 0xbd2: "VANDNPS", 0x195b: "VPADDQ", 0x4dd: "FPREM", 0x1c3d: "VPADDW",
0x23c9: "AESENC", 0x24bc: "PALIGNR", 0x1fad: "PMINSB", 0xe86: "PCMPGTW", 0x36c: "SHLD",
0x14f: "LDS", 0x1c2e: "VPADDB", 0x700: "VMRUN", 0xbdb: "VANDNPD", 0x190: "XLAT",
0xd4: "XCHG", 0x4d4: "FINCSTP", 0x197d: "MOVDQ2Q", 0x1af9: "PMINSW", 0x6a8: "SMSW",
0x1d4a: "VPSIGNB", 0x10c0: "XRSTOR", 0x249f: "VBLENDPD", 0xc0: "JGE", 0x134a: "VCMPNLT_UQPS",
0x1753: "VCMPORDSD", 0x248c: "VBLENDPS", 0x45e: "FTST", 0x1a7b: "CVTTPD2DQ",
0x15c1: "VCMPORDSS", 0x14dc: "VCMPNLT_UQPD", 0x216c: "VFNMSUB132SS", 0x10c8: "XRSTOR64",
0x29: "AND", 0xb72: "VRSQRTPS", 0x10f8: "CLFLUSH", 0x1cb0: "PSHUFB", 0x437: "FLDENV",
0xda: "MOV", 0xf91: "PSHUFD", 0xc5: "JLE", 0x5c5: "FEDISI", 0xe8f: "VPCMPGTW",
0x7f0: "PFCMPEQ", 0x168a: "VCMPORD_SSS", 0xf89: "PSHUFW", 0x24d7: "VPEXTRB",
0x1aa6: "VCVTDQ2PD", 0xf60: "VMOVQ", 0x478: "FLDL2E", 0x24f0: "VPEXTRD", 0x1d15: "VPHSUBW",
0x2268: "VFNMSUB213PS", 0x21d5: "VFMADD213PD", 0x720: "STGI", 0x4b2: "FPATAN",
0x42c: "FST", 0x168: "INT 3", 0x58d: "FIST", 0x26a8: "VMCLEAR", 0x1e62: "PMOVSXBQ",
0x42: "AAA", 0x1d26: "VPHSUBD", 0xa28: "CVTTPS2PI", 0x113c: "CMPNEQPS", 0x154c: "VCMPGE_OQPD",
0x1b55: "LDDQU", 0xb60: "RSQRTPS", 0xc40: "VADDPD", 0x79f: "PFRCP", 0xca8: "CVTSS2SD",
0x217a: "VFNMSUB132SD", 0x627: "FDIVRP", 0x636: "FBLD", 0x361: "CPUID", 0x251: "RDTSC",
0x24b2: "VPBLENDW", 0xd12: "VCVTPS2DQ", 0x1b0f: "VPOR", 0xc38: "VADDPS", 0x762: "PI2FW",
0xd65: "MINPS", 0x17bc: "VCMPEQ_OSSD", 0x1b9a: "VPMULUDQ", 0xdf2: "MAXSD",
0x203d: "VPMULLD", 0x54d: "FIDIVR", 0xabc: "VUCOMISS", 0x887: "MOVDDUP", 0x1cb8: "VPSHUFB",
0x1d2f: "PHSUBSW", 0x2628: "VPCMPISTRI", 0xdeb: "MAXSS", 0x1a22: "VPAVGB",
0x16c0: "VCMPFALSE_OSSS", 0xd6c: "MINPD", 0x4e4: "FYL2XP1", 0xac6: "VUCOMISD",
0x238e: "VFNMSUB231PD", 0x1836: "VCMPNGE_UQSD", 0xc31: "ADDSD", 0x6d8: "VMXOFF",
0x1945: "PSRLQ", 0x127c: "VCMPNEQPS", 0x1927: "PSRLW", 0x1a39: "PSRAD", 0x696: "SIDT",
0xe5e: "PACKSSWB", 0x10a8: "XSAVE", 0x140e: "VCMPNEQPD", 0xfa: "CDQ", 0xc2a: "ADDSS",
0x16a4: "VCMPNGE_UQSS", 0x2424: "CRC32", 0x23c0: "VAESIMC", 0x1ff1: "PMAXSB",
0x2504: "VEXTRACTPS", 0x1800: "VCMPNLT_UQSD", 0x1bf2: "VPSUBB", 0x1f7a: "VPMOVZXWQ",
0x13ac: "VCMPNEQ_OSPS", 0xa02: "MOVNTSS", 0x251d: "VEXTRACTF128", 0x1b15: "PADDSB",
0x75: "IMUL", 0x3db: "RCR", 0x14bf: "VCMPUNORD_SPD", 0x3d6: "RCL", 0xa0b: "MOVNTSD",
0x153e: "VCMPNEQ_OSPD", 0x166e: "VCMPNLT_UQSS", 0xd3e: "SUBSD", 0x13f: "SCAS",
0x25a0: "PCLMULQDQ", 0x7a6: "PFRSQRT", 0x2551: "PINSRD", 0x618: "FSUBRP", 0x5b: "PUSHA",
0x1a03: "VPMAXUB", 0x1130: "CMPUNORDPS", 0x202c: "VPMAXUD", 0x458: "FABS",
0x1e6c: "VPMOVSXBQ", 0x148c: "VCMPTRUEPD", 0x23e: "FEMMS", 0x162a: "VCMPEQ_OSSS",
0x21ef: "VFMADD213SD", 0x1e57: "VPMOVSXBD", 0x117f: "CMPUNORDPD", 0x18f4: "VMPTRST",
0x18e8: "CMPXCHG16B", 0x12fa: "VCMPTRUEPS", 0x12c0: "VCMPNGTPS", 0x1c74: "FNCLEX",
0x1229: "CMPNEQSD", 0x175e: "VCMPEQ_UQSD", 0x56e: "FCMOVU", 0x1025: "EXTRQ",
0x2580: "DPPD", 0x2e2: "CMOVGE", 0x252b: "PINSRB", 0x15cc: "VCMPEQ_UQSS", 0x1d01: "VPMADDUBSW",
0x11da: "CMPNEQSS", 0x22ed: "VFMADD231PD", 0x50e: "FSIN", 0x1bf: "IN", 0x55d: "FCMOVE",
0x43f: "FLDCW", 0x2573: "DPPS", 0x555: "FCMOVB", 0x192e: "VPSRLW", 0x10b8: "LFENCE",
0xa8a: "CVTSD2SI", 0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x194c: "VPSRLQ", 0x609: "FMULP",
0x9a9: "VMOVAPD", 0x1644: "VCMPLE_OQSS", 0x2c4: "CMOVNS", 0x5a3: "FCMOVNE",
0x288: "CMOVNO", 0x1a72: "VPMULHW", 0x193d: "VPSRLD", 0xa6c: "CVTPS2PI", 0x1cd2: "PHADDD",
0xc94: "CVTPS2PD", 0x1e21: "VPABSW", 0x17d6: "VCMPLE_OQSD", 0x9a0: "VMOVAPS",
0x1c01: "VPSUBW", 0x80a: "PMULHRW", 0x990: "MOVAPS", 0x798: "PFMIN", 0xf4d: "MOVD",
0x91e: "MOVHPS", 0xc58: "MULPS", 0x125b: "VCMPLTPS", 0x368: "BT", 0x998: "MOVAPD",
0x1380: "VCMPNGE_UQPS", 0x1b8: "JRCXZ", 0xc5f: "MULPD", 0x127: "MOVS", 0x6b4: "INVLPG",
0xf53: "MOVQ", 0xd89: "VMINPD", 0x1e29: "PABSD", 0x11b: "SAHF", 0x13d4: "VCMPTRUE_USPS",
0x769: "PI2FD", 0x1e0b: "PABSB", 0x1a13: "VPANDN", 0xe52: "VPUNPCKLDQ", 0x62f: "FDIVP",
0x1c18: "PSUBQ", 0x420: "FDIVR", 0x41a: "FDIV", 0x1566: "VCMPTRUE_USPD", 0x74d: "PREFETCH",
0x1001: "EMMS", 0xd81: "VMINPS", 0x22e0: "VFMADD231PS", 0x2276: "VFNMSUB213PD",
0xa80: "CVTSS2SI", 0x926: "MOVHPD", 0x29f: "CMOVZ", 0x1a4f: "VPAVGW", 0xff: "CQO",
0x1c10: "VPSUBD", 0x2cc: "CMOVP", 0x1575: "VCMPEQSS", 0x2bd: "CMOVS", 0x1e4d: "PMOVSXBD",
0x2466: "VROUNDSS", 0x1c1f: "VPSUBQ", 0x2db: "CMOVL", 0x1907: "ADDSUBPS", 0x281: "CMOVO",
0x2b6: "CMOVA", 0x290: "CMOVB", 0xec1: "PUNPCKHBW", 0x261d: "PCMPISTRI", 0x2f2: "CMOVG",
0x1990: "VPMOVMSKB", 0x2404: "AESDECLAST", 0x82c: "MOVUPD", 0x20a0: "VFMSUBADD132PD",
0x1bbf: "VPSADBW", 0x2453: "VROUNDPD", 0x6ae: "LMSW", 0x205f: "INVEPT", 0x39f: "MOVZX",
0xba4: "ANDPS", 0x2090: "VFMSUBADD132PS", 0x824: "MOVUPS", 0x1614: "VCMPGTSS",
0x1a57: "PMULHUW", 0x2586: "VDPPD", 0x24e0: "PEXTRD", 0x15ef: "VCMPFALSESS",
0x1b: "OR", 0x18b2: "VPEXTRW", 0x1adf: "VPSUBSB", 0x1094: "FXRSTOR", 0x21d: "CLTS",
0x1844: "VCMPNGT_UQSD", 0x15e4: "VCMPNGTSS", 0x5e4: "FRSTOR", 0x1781: "VCMPFALSESD",
0x48f: "FLDLN2", 0x2510: "VINSERTF128", 0x1af0: "VPSUBSW", 0x1b91: "PMULUDQ",
0x56: "DEC", 0x139c: "VCMPFALSE_OSPS", 0x427: "FLD", 0x1f8f: "VPMOVZXDQ", 0x245d: "ROUNDSS",
0x9da: "VCVTSI2SS", 0x18aa: "PEXTRW", 0x3cc: "ROL", 0x20d7: "VFMADD132SD",
0x1176: "CMPLEPD", 0xcdd: "VCVTSD2SS", 0x5fa: "FUCOMP", 0x1ce: "JMP", 0x1707: "VCMPEQSD",
0xce8: "CVTDQ2PS", 0x16eb: "VCMPGT_OQSS", 0x5d5: "FUCOMI", 0x110e: "LZCNT",
0xb94: "VRCPPS", 0x19fb: "PMAXUB", 0x1cda: "VPHADDD", 0x9e5: "VCVTSI2SD", 0x187d: "VCMPGT_OQSD",
0x3d1: "ROR", 0x22b: "INVD", 0xa9f: "VCVTSD2SI", 0x23f3: "AESDEC", 0x123d: "CMPNLESD",
0x354: "SETLE", 0x22c0: "VFMSUBADD231PS", 0x2348: "VFNMADD231PS", 0x10af: "XSAVE64",
0xed8: "PUNPCKHWD", 0x1e81: "VPMOVSXWD", 0xc9e: "CVTPD2PS", 0x890: "VMOVHLPS",
0x22d0: "VFMSUBADD231PD", 0xa76: "CVTPD2PI", 0x11ee: "CMPNLESS", 0x1eb6: "PMULDQ",
0x1e96: "VPMOVSXWQ", 0x173d: "VCMPNLTSD", 0x2356: "VFNMADD231PD", 0x1ca9: "FSTSW",
0x745: "RDTSCP", 0x10d2: "MFENCE", 0x20ca: "VFMADD132SS", 0x1fe0: "PMINUD",
0x5bf: "FENI", 0x68: "BOUND", 0x2440: "VROUNDPS", 0xfa2: "PSHUFLW", 0xc84: "VMULSS",
0x1852: "VCMPFALSE_OSSD", 0xd07: "VCVTDQ2PS", 0x1589: "VCMPLESS", 0x44c: "FNOP",
0x1146: "CMPNLTPS", 0x1287: "VCMPNLTPS", 0x487: "FLDLG2", 0x223: "SYSRET",
0x1c6d: "FSTCW", 0x2216: "VFMSUB213SS", 0x72c: "SKINIT", 0xbba: "VANDPD", 0x497: "FLDZ",
0x33: "SUB", 0x1cc9: "VPHADDW", 0x659: "NEG", 0x1fcf: "PMINUW", 0xde4: "MAXPD",
0x1366: "VCMPORD_SPS", 0x133: "STOS", 0x23aa: "VFNMSUB231SD", 0x1725: "VCMPUNORDSD",
0x81b: "PAVGUSB", 0x14f8: "VCMPORD_SPD", 0xddd: "MAXPS", 0x19c1: "PMINUB",
0x1bde: "VMASKMOVDQU", 0x63c: "FBSTP", 0x1899: "PINSRW", 0x1f65: "VPMOVZXWD",
0x1fd7: "VPMINUW", 0x180e: "VCMPNLE_UQSD", 0x18a: "SALC", 0x24cf: "PEXTRB",
0x8d5: "VUNPCKLPS", 0x167c: "VCMPNLE_UQSS", 0xf67: "MOVDQA", 0x15ab: "VCMPNLTSS",
0x1b82: "PSLLQ", 0xa14: "VMOVNTPS", 0x1fe8: "VPMINUD", 0x95f: "PREFETCHNTA",
0x8e0: "VUNPCKLPD", 0x2479: "VROUNDSD", 0x2645: "VAESKEYGENASSIST", 0x1ae8: "PSUBSW",
0x176b: "VCMPNGESD", 0x1c54: "FNSTENV", 0x1ca1: "FNSTSW", 0x118b: "CMPNEQPD",
0x1a48: "PAVGW", 0x9f9: "MOVNTPD", 0x1505: "VCMPEQ_USPD", 0x5cd: "FSETPM",
0x1dbc: "BLENDVPS", 0x2198: "VFMADDSUB213PD", 0xb: "ADD", 0x15d9: "VCMPNGESS",
0x1f: "ADC", 0x1ad7: "PSUBSB", 0x1dc6: "BLENDVPD", 0xecc: "VPUNPCKHBW", 0x25f: "RDPMC",
0x9f0: "MOVNTPS", 0xbc2: "ANDNPS", 0x13ed: "VCMPLTPD", 0x1a1b: "PAVGB", 0xdf: "LEA",
0x1a9a: "VCVTTPD2DQ", 0xe7c: "VPCMPGTB", 0xea2: "VPCMPGTD", 0x46a: "FLD1",
0x1bad: "VPMADDWD", 0x17e3: "VCMPUNORD_SSD", 0x14a: "LES", 0x313: "SETZ", 0x1fa3: "VPCMPGTQ",
0xc8c: "VMULSD", 0x21c8: "VFMADD213PS", 0x15b6: "VCMPNLESS", 0x864: "MOVHLPS",
0x2052: "VPHMINPOSUW", 0x1e30: "VPABSD", 0x1a2a: "PSRAW", 0x7b6: "PFADD", 0x2080: "VFMADDSUB132PD",
0xad8: "COMISD", 0x13ba: "VCMPGE_OQPS", 0xe09: "VMAXSS", 0x121d: "CMPUNORDSD",
0x4f4: "FSINCOS", 0xad0: "COMISS", 0x2070: "VFMADDSUB132PS", 0xb86: "RCPPS",
0x2126: "VFNMADD132PD", 0x446: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcbc: "VCVTPS2PD",
0x1ba4: "PMADDWD", 0xbab: "ANDPD", 0x1320: "VCMPLE_OQPS", 0x1776: "VCMPNGTSD",
0x2380: "VFNMSUB231PS", 0x643: "FUCOMIP", 0xc74: "VMULPS", 0x2118: "VFNMADD132PS",
0x38: "DAS", 0x14b2: "VCMPLE_OQPD", 0x17a: "IRET", 0x3c5: "BSWAP", 0xe19: "PUNPCKLBW",
0x2013: "PMAXUW", 0x2611: "VPCMPISTRM", 0x1b64: "PSLLW", 0x1651: "VCMPUNORD_SSS",
0x2230: "VFNMADD213PS", 0xa60: "VCVTTSD2SI", 0x2321: "VFMSUB231PD", 0x138e: "VCMPNGT_UQPS",
0x1c65: "FNSTCW", 0x2470: "ROUNDSD", 0x119f: "CMPNLEPD", 0x24e8: "PEXTRQ",
0x1a6a: "PMULHW", 0x1cec: "VPHADDSW", 0x593: "FISTP", 0x1f70: "PMOVZXWQ", 0xcc7: "VCVTPD2PS",
0x16f8: "VCMPTRUE_USSS", 0xc50: "VADDSD", 0x1db2: "PBLENDVB", 0x6ce: "VMRESUME",
0xab3: "UCOMISD", 0x1f5b: "PMOVZXWD", 0xa33: "CVTTPD2PI", 0xaaa: "UCOMISS",
0xe68: "VPACKSSWB", 0xc48: "VADDSS", 0xf99: "PSHUFHW", 0x188a: "VCMPTRUE_USSD",
0x6e9: "MWAIT"}

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
            pydi = ( di.offset, di.size, asm, di.instructionHex.p )
            instruction_off += di.size
            yield pydi

        di         = result[used - 1]
        delta      = di.offset - codeOffset + result[used -1].size
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
    return list( DecodeGenerator(offset, code, type) )

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
        print "Bad meta-flags: %d", realvalue
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
        elif type == OPERAND_ABSOLUTE_ADDRESS:
            self.size = args[0]
            self.disp = int(args[1])
            self.dispSize = args[2]
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
            return Operand(OPERAND_MEMORY, di.base, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize)
        elif operand.type == O_SMEM:
            return Operand(OPERAND_MEMORY, None, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize)
        elif operand.type == O_DISP:
            return Operand(OPERAND_ABSOLUTE_ADDRESS, operand.size, di.disp, di.dispSize)
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


def DecomposeGenerator(codeOffset, code, dt):
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
        codeInfo = _CodeInfo(_OffsetType(codeOffset), _OffsetType(0), cast(p_code, c_char_p), codeLen, dt, 0)
        status = internal_decompose(byref(codeInfo), byref(result), MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        delta = 0
        for index in xrange(used):
            di = result[index]
            yield Instruction(di, code[instruction_off : instruction_off + di.size], dt)
            delta += di.size
            instruction_off += di.size

        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, instruction_off)
        codeLen    = codeLen - delta

def Decompose(offset, code, type = Decode32Bits):
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

    @rtype:  TODO
    @return: TODO
    @raise ValueError: Invalid arguments.
    """
    return list( DecomposeGenerator(offset, code, type) )
