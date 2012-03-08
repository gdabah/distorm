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

Mnemonics = {0x66e: "SLDT", 0x62: "POPA", 0x8f3: "UNPCKHPS", 0x115: "POPF", 0x11c4: "CMPLTSS",
0x864: "VMOVSD", 0x78e: "PFPNACC", 0xb19: "VMOVMSKPD", 0x73c: "INVLPGA", 0x8fd: "UNPCKHPD",
0x270: "SYSEXIT", 0x7b7: "PFSUB", 0x1213: "CMPLTSD", 0x1a68: "VPMULHUW", 0x1d40: "VPHSUBSW",
0x12bd: "VCMPNGEPS", 0x85c: "VMOVSS", 0x6f: "ARPL", 0x52f: "FICOMP", 0x162: "RETF",
0x452: "FCHS", 0x112f: "CMPLEPS", 0xef7: "PUNPCKHDQ", 0x2403: "VAESDEC", 0x5f3: "FUCOM",
0x12a5: "VCMPORDPS", 0x19b6: "PSUBUSW", 0x1b50: "PXOR", 0x1e1a: "VPABSB", 0x24a: "WRMSR",
0x12b0: "VCMPEQ_UQPS", 0x22b8: "VFMADDSUB231PD", 0x7ce: "PFMAX", 0x16d8: "VCMPNEQ_OSSS",
0x2246: "VFNMADD213PD", 0x3bd: "MOVNTI", 0x7c5: "PFCMPGT", 0x236c: "VFNMADD231SS",
0x2452: "ROUNDPD", 0x12f8: "VCMPGTPS", 0xba4: "VRCPSS", 0x213c: "VFNMADD132SS",
0x144f: "VCMPNGEPD", 0x2211: "VFMSUB213PD", 0x186a: "VCMPNEQ_OSSD", 0x2681: "VPSLLDQ",
0x797: "PFCMPGE", 0x148a: "VCMPGTPD", 0x1a8e: "CVTDQ2PD", 0x121c: "CMPLESD",
0xae: "JNS", 0xddd: "VDIVSD", 0xb7: "JNP", 0x250a: "EXTRACTPS", 0x1f4e: "PMOVZXBQ",
0x9c: "JNZ", 0x5dd: "FCOMI", 0xeeb: "VPUNPCKHWD", 0x1f39: "PMOVZXBD", 0x1ad5: "VMOVNTDQ",
0x1e7f: "PMOVSXWD", 0x1109: "POPCNT", 0x8a: "JNO", 0x1c9a: "FNSAVE", 0x1a5: "LOOP",
0xb0e: "VMOVMSKPS", 0x470: "FLDL2T", 0x12d: "CMPS", 0x40d: "FSUB", 0xda9: "DIVPS",
0x1d26: "PHSUBD", 0x11bb: "CMPEQSS", 0x1e7: "CMC", 0xd04: "CVTTPS2DQ", 0xdb0: "DIVPD",
0xf61: "VMOVD", 0x104: "CALL FAR", 0x1d7d: "PMULHRSW", 0x1d87: "VPMULHRSW",
0x1d15: "PHSUBW", 0x120a: "CMPEQSD", 0x3b7: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x105f: "VHADDPS", 0x206f: "INVVPID", 0x20f: "LSL", 0x1668: "VCMPNEQ_USSS",
0x1056: "VHADDPD", 0x38b: "LSS", 0x20f9: "VFMSUB132PD", 0x121: "LAHF", 0x7f1: "PFACC",
0x808: "PFRCPIT2", 0xe2c: "VPUNPCKLBW", 0x7d5: "PFRCPIT1", 0x1fa2: "PCMPGTQ",
0x4a4: "FYL2X", 0x1824: "VCMPORD_SSD", 0x193e: "PSRLD", 0x10f8: "SFENCE", 0xcfa: "CVTPS2DQ",
0x24b1: "PBLENDW", 0x21b0: "VFMSUBADD213PS", 0xe7b: "PCMPGTB", 0xea1: "PCMPGTD",
0x23d9: "VAESENC", 0x95c: "VMOVSHDUP", 0x259e: "MPSADBW", 0x14f2: "VCMPNLE_UQPD",
0x70f: "VMMCALL", 0x1034: "INSERTQ", 0x2254: "VFNMADD213SS", 0x9c4: "CVTPI2PD",
0x16f: "INT", 0x1d92: "VPERMILPS", 0x1e2: "HLT", 0x204e: "PHMINPOSUW", 0x5b6: "FCMOVNU",
0x7b: "INS", 0x64c: "FCOMIP", 0x9ba: "CVTPI2PS", 0x2262: "VFNMADD213SD", 0xeb4: "PACKUSWB",
0xe4: "CBW", 0x720: "VMSAVE", 0x10e: "PUSHF", 0x654: "NOT", 0x59a: "FCMOVNB",
0x245: "NOP", 0x4ed: "FSQRT", 0x1d9d: "VPERMILPD", 0x51: "INC", 0x239: "UD2",
0xfec: "VPCMPEQW", 0x2617: "PCMPISTRM", 0x1ed8: "VPCMPEQQ", 0x1158: "CMPNLEPS",
0x1831: "VCMPEQ_USSD", 0x1409: "VCMPUNORDPD", 0x602: "FADDP", 0x145: "RET",
0xfff: "VPCMPEQD", 0x1fce: "VPMINSD", 0x2544: "VPINSRB", 0xfd9: "VPCMPEQB",
0x1905: "ADDSUBPD", 0x1092: "FXSAVE64", 0x169f: "VCMPEQ_USSS", 0x1d5b: "PSIGNW",
0x1eb3: "VPMOVSXDQ", 0x2012: "VPMAXSD", 0x35b: "SETG", 0x2001: "VPMAXSB", 0x327: "SETA",
0x306: "SETB", 0x269d: "STMXCSR", 0x347: "SETL", 0x20ec: "VFMSUB132PS", 0x2f9: "SETO",
0xbd2: "ANDNPD", 0x1111: "BSR", 0x8bf: "VMOVDDUP", 0x1b47: "VPMAXSW", 0x1d6c: "PSIGND",
0x33a: "SETP", 0x1d4a: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x159b: "VCMPUNORDSS",
0x3ab: "BSF", 0x26ca: "VMXON", 0xbba: "VANDPS", 0x6f8: "XSETBV", 0x1c3: "OUT",
0x67f: "LTR", 0x2572: "VPINSRD", 0xa5c: "VCVTTSS2SI", 0x2670: "VPSRLDQ", 0x4cb: "FDECSTP",
0x2668: "PSRLDQ", 0x1878: "VCMPGE_OQSD", 0x2679: "PSLLDQ", 0x514: "FCOS", 0x4ba: "FXTRACT",
0x16e6: "VCMPGE_OQSS", 0x1eec: "VMOVNTDQA", 0x1528: "VCMPNGT_UQPD", 0x3fa: "FMUL",
0x13cf: "VCMPGT_OQPS", 0x610: "FCOMPP", 0x77f: "PF2ID", 0xf5: "CWD", 0x1335: "VCMPUNORD_SPS",
0x2ea: "CMOVLE", 0xfbc: "VPSHUFHW", 0x1561: "VCMPGT_OQPD", 0x1ceb: "PHADDSW",
0x778: "PF2IW", 0xa26: "VMOVNTPD", 0x406: "FCOMP", 0x8c9: "UNPCKLPS", 0x1bda: "MASKMOVDQU",
0x565: "FCMOVBE", 0x14ad: "VCMPLT_OQPD", 0xe19: "VMAXSD", 0x1421: "VCMPNLTPD",
0x98c: "PREFETCHT2", 0x980: "PREFETCHT1", 0x974: "PREFETCHT0", 0x8d3: "UNPCKLPD",
0xa46: "CVTTSS2SI", 0x663: "DIV", 0x1ea9: "PMOVSXDQ", 0x1612: "VCMPGESS", 0xef: "CDQE",
0x26a6: "VSTMXCSR", 0x53e: "FISUBR", 0x1fbd: "VPMINSB", 0x2204: "VFMSUB213PS",
0x131b: "VCMPLT_OQPS", 0x11cd: "CMPLESS", 0x1b09: "VPMINSW", 0x1c65: "FSTENV",
0x17a4: "VCMPGESD", 0x1ddf: "VPTEST", 0x537: "FISUB", 0x205: "STD", 0xf18: "VPACKSSDW",
0x3d: "XOR", 0xc84: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x268a: "LDMXCSR",
0x1175: "CMPLTPD", 0xbec: "ORPS", 0x1f01: "VPACKUSDW", 0x620: "FSUBP", 0x674: "STR",
0x413: "FSUBR", 0x1126: "CMPLTPS", 0x230f: "VFMADD231SD", 0x26df: "PAUSE",
0x1a98: "CVTPD2DQ", 0x372: "RSM", 0xb5f: "VSQRTSD", 0xbf8: "VORPS", 0x2190: "VFMADDSUB213PS",
0x10a5: "FXRSTOR64", 0x1442: "VCMPEQ_UQPD", 0x907: "VUNPCKHPS", 0x1cfe: "PMADDUBSW",
0x1360: "VCMPNLE_UQPS", 0x1b73: "VPSLLW", 0x1bd0: "MASKMOVQ", 0x1c8: "CALL",
0xb56: "VSQRTSS", 0x19e7: "PADDUSB", 0x1025: "VMREAD", 0x10ec: "XSAVEOPT64",
0x912: "VUNPCKHPD", 0xd4d: "VSUBPS", 0xcda: "VCVTSS2SD", 0x2418: "VAESDECLAST",
0x1070: "HSUBPS", 0xa9c: "VCVTSS2SI", 0x25de: "VPBLENDVB", 0x17ae: "VCMPGTSD",
0x57f: "FILD", 0xae8: "VCOMISS", 0x1068: "HSUBPD", 0x23a4: "VFNMSUB231SS",
0x1a48: "VPSRAD", 0x129a: "VCMPNLEPS", 0x3ea: "SAL", 0x214: "SYSCALL", 0xb84: "VRSQRTSS",
0x257b: "VPINSRQ", 0xfb3: "VPSHUFD", 0x1e40: "PMOVSXBW", 0x1a39: "VPSRAW",
0x142c: "VCMPNLEPD", 0x3f4: "FADD", 0x3ef: "SAR", 0x1ac4: "MOVNTQ", 0x2645: "AESKEYGENASSIST",
0xf0e: "PACKSSDW", 0x21ea: "VFMADD213SS", 0xf7f: "VMOVDQA", 0x8b4: "VMOVSLDUP",
0x4fd: "FRNDINT", 0x196b: "PMULLW", 0xdbe: "DIVSD", 0xafa: "MOVMSKPS", 0x2023: "VPMAXUW",
0xdcd: "VDIVPD", 0x1e4a: "VPMOVSXBW", 0x1e94: "PMOVSXWQ", 0x203d: "PMULLD",
0xf88: "VMOVDQU", 0x229a: "VFNMSUB213SD", 0x297: "CMOVAE", 0x14a0: "VCMPEQ_OSPD",
0xdc5: "VDIVPS", 0x93: "JAE", 0xb04: "MOVMSKPD", 0xdb7: "DIVSS", 0x1ca2: "FSAVE",
0x1ecf: "PCMPEQQ", 0xfc6: "VPSHUFLW", 0xfe3: "PCMPEQW", 0x2693: "VLDMXCSR",
0x2106: "VFMSUB132SS", 0x11b1: "CMPORDPD", 0xb95: "RCPSS", 0x1b82: "VPSLLD",
0x668: "IDIV", 0x1437: "VCMPORDPD", 0xfd0: "PCMPEQB", 0xff6: "PCMPEQD", 0x1b91: "VPSLLQ",
0x1f58: "VPMOVZXBQ", 0x21c0: "VFMSUBADD213PD", 0x25d3: "VBLENDVPD", 0x1162: "CMPORDPS",
0xf23: "PUNPCKLQDQ", 0x19e0: "VPAND", 0x1472: "VCMPNEQ_OQPD", 0x1046: "HADDPD",
0x1924: "VADDSUBPS", 0x18dc: "VSHUFPD", 0x22a8: "VFMADDSUB231PS", 0xd65: "VSUBSD",
0xb44: "VSQRTPS", 0x936: "MOVSHDUP", 0x237a: "VFNMADD231SD", 0x6c4: "VMLAUNCH",
0x1f18: "VMASKMOVPD", 0x104e: "HADDPS", 0x12e0: "VCMPNEQ_OQPS", 0xe38: "PUNPCKLWD",
0x16ba: "VCMPNGT_UQSS", 0xb4d: "VSQRTPD", 0xd5d: "VSUBSS", 0x18d3: "VSHUFPS",
0x15a8: "VCMPNEQSS", 0x1b64: "VLDDQU", 0x163f: "VCMPLT_OQSS", 0x26b0: "RDRAND",
0x1b2e: "PADDSW", 0x137b: "VCMPEQ_USPS", 0xbf2: "ORPD", 0x1a14: "PANDN", 0x4ab: "FPTAN",
0x546: "FIDIV", 0x17d1: "VCMPLT_OQSD", 0x26b8: "VMPTRLD", 0x231c: "VFMSUB231PS",
0x173a: "VCMPNEQSD", 0x1ec6: "VPMULDQ", 0x196: "LOOPNZ", 0x1277: "VCMPUNORDPS",
0x3e5: "SHR", 0x37c: "SHRD", 0x6e0: "MONITOR", 0x23e2: "AESENCLAST", 0x843: "MOVSD",
0x18a9: "VPINSRW", 0x718: "VMLOAD", 0x91d: "MOVLHPS", 0x8ab: "VMOVLPD", 0x197c: "MOVQ2DQ",
0xb34: "SQRTSS", 0x258a: "VDPPS", 0xd3f: "SUBSS", 0x3b0: "MOVSX", 0x940: "VMOVLHPS",
0x8a2: "VMOVLPS", 0xf02: "VPUNPCKHDQ", 0x1ab9: "VCVTPD2DQ", 0x3e0: "SHL", 0x83c: "MOVSS",
0x256a: "PINSRQ", 0x786: "PFNACC", 0xf77: "MOVDQU", 0x80: "OUTS", 0x1bf3: "PSUBB",
0x377: "BTS", 0x390: "BTR", 0x17fa: "VCMPNEQ_USSD", 0x690: "SGDT", 0x2302: "VFMADD231SS",
0x506: "FSCALE", 0x1c02: "PSUBW", 0x119d: "CMPNLTPD", 0x1ef7: "PACKUSDW", 0x20a: "LAR",
0x3a6: "BTC", 0x214a: "VFNMADD132SD", 0x145a: "VCMPNGTPD", 0x1f2e: "VPMOVZXBW",
0x2113: "VFMSUB132SD", 0x23c0: "AESIMC", 0x400: "FCOM", 0x1f43: "VPMOVZXBD",
0x1919: "VADDSUBPD", 0x1c93: "FINIT", 0x1200: "CMPORDSS", 0x231: "WBINVD",
0x19da: "PAND", 0x24cd: "VPALIGNR", 0x124f: "CMPORDSD", 0x1b56: "VPXOR", 0xa1: "JBE",
0x464: "FXAM", 0x10e2: "XSAVEOPT", 0x65e: "MUL", 0x19d1: "VPMINUB", 0x1b36: "VPADDSW",
0x1b3f: "PMAXSW", 0x2557: "VINSERTPS", 0x13eb: "VCMPEQPD", 0x5ec: "FFREE",
0x1f0c: "VMASKMOVPS", 0x18e5: "CMPXCHG8B", 0x200a: "PMAXSD", 0x1b25: "VPADDSB",
0x10: "PUSH", 0x25bc: "VPCLMULQDQ", 0x1259: "VCMPEQPS", 0x7df: "PFRSQIT1",
0x243f: "ROUNDPS", 0x2ff: "SETNO", 0x6f0: "XGETBV", 0x1fc6: "PMINSD", 0x1c2f: "PADDB",
0x4c3: "FPREM1", 0x200: "CLD", 0x521: "FIMUL", 0xc0d: "XORPD", 0x1ec: "CLC",
0x431: "FSTP", 0x249e: "BLENDPD", 0x19fa: "PADDUSW", 0x1c8b: "FNINIT", 0x319: "SETNZ",
0x195c: "PADDQ", 0xc06: "XORPS", 0x228c: "VFNMSUB213SS", 0x333: "SETNS", 0x51a: "FIADD",
0x340: "SETNP", 0xf48: "VPUNPCKHQDQ", 0xd31: "SUBPS", 0x123b: "CMPNLTSD", 0x679: "LLDT",
0x222b: "VFMSUB213SD", 0x1dd8: "PTEST", 0x2166: "VFNMSUB132PD", 0x279: "GETSEC",
0x1d74: "VPSIGND", 0x1ab: "JCXZ", 0x11ec: "CMPNLTSS", 0x34d: "SETGE", 0x111d: "CMPEQPS",
0x1bbf: "PSADBW", 0x26d7: "MOVSXD", 0x2158: "VFNMSUB132PS", 0x185: "AAD", 0x23ee: "VAESENCLAST",
0xf3c: "PUNPCKHQDQ", 0x87d: "MOVLPD", 0x19f0: "VPADDUSW", 0x12d3: "VCMPFALSEPS",
0x180: "AAM", 0xf2f: "VPUNPCKLQDQ", 0xd7b: "MINSS", 0x1c4d: "PADDD", 0x1465: "VCMPFALSEPD",
0xe43: "VPUNPCKLWD", 0x875: "MOVLPS", 0x72e: "CLGI", 0x4c: "AAS", 0x139: "LODS",
0x2d3: "CMOVNP", 0xd82: "MINSD", 0x1f6: "CLI", 0xa51: "CVTTSD2SI", 0x528: "FICOM",
0x1f24: "PMOVZXBW", 0xc2b: "ADDPD", 0x75f: "PREFETCHW", 0x1344: "VCMPNEQ_USPS",
0xc1c: "VXORPD", 0x1b12: "POR", 0x16: "POP", 0x2433: "VPERM2F128", 0x19e: "LOOPZ",
0x1acc: "MOVNTDQ", 0x1dc: "INT1", 0x382: "CMPXCHG", 0x1e03: "VBROADCASTF128",
0x151a: "VCMPNGE_UQPD", 0x1cc9: "PHADDW", 0xc14: "VXORPS", 0x14d6: "VCMPNEQ_USPD",
0xc24: "ADDPS", 0x801: "PFMUL", 0x69c: "LGDT", 0x684: "VERR", 0x68a: "VERW",
0x1078: "VHSUBPD", 0x1973: "VPMULLW", 0x84a: "VMOVUPS", 0x174: "INTO", 0x1c84: "FCLEX",
0x1081: "VHSUBPS", 0xcba: "CVTSD2SS", 0x480: "FLDPI", 0x1e22: "PABSW", 0xe09: "VMAXPD",
0x1d3: "JMP FAR", 0xebe: "VPACKUSWB", 0x576: "FUCOMPP", 0x853: "VMOVUPD", 0x81b: "PSWAPD",
0x1c3e: "PADDW", 0x1b7b: "PSLLD", 0x745: "SWAPGS", 0x885: "MOVSLDUP", 0x9ce: "CVTSI2SS",
0x17b8: "VCMPTRUESD", 0x11d6: "CMPUNORDSS", 0xd25: "VCVTTPS2DQ", 0xb3c: "SQRTSD",
0x1df5: "VBROADCASTSD", 0x1c11: "PSUBD", 0xce: "TEST", 0x39a: "LGS", 0x1626: "VCMPTRUESS",
0x266: "SYSENTER", 0x9d8: "CVTSI2SD", 0x1750: "VCMPNLESD", 0x1db1: "VTESTPD",
0x98: "JZ", 0xdd5: "VDIVSS", 0xbff: "VORPD", 0xb3: "JP", 0xaa: "JS", 0xbc: "JL",
0xb71: "RSQRTSS", 0x1da8: "VTESTPS", 0x86: "JO", 0xe01: "VMAXPS", 0x19a3: "PSUBUSB",
0xca: "JG", 0x1de7: "VBROADCASTSS", 0xa6: "JA", 0x8f: "JB", 0xe9: "CWDE", 0x13ff: "VCMPLEPD",
0x103d: "VMWRITE", 0x126d: "VCMPLEPS", 0x198e: "PMOVMSKB", 0x254d: "INSERTPS",
0x2600: "PCMPESTRI", 0x26d1: "WAIT", 0x1536: "VCMPFALSE_OSPD", 0x25e9: "PCMPESTRM",
0xe4f: "PUNPCKLDQ", 0xc6e: "MULSS", 0xd55: "VSUBPD", 0x116c: "CMPEQPD", 0x1796: "VCMPNEQ_OQSD",
0xaf1: "VCOMISD", 0xd99: "VMINSS", 0x1c54: "VPADDD", 0x258: "RDMSR", 0x1d63: "VPSIGNW",
0x1b1: "JECXZ", 0xc75: "MULSD", 0x154: "ENTER", 0x2425: "MOVBE", 0x101b: "VZEROALL",
0xda1: "VMINSD", 0x1604: "VCMPNEQ_OQSS", 0x7e9: "PFSUBR", 0x12ee: "VCMPGEPS",
0x19ac: "VPSUBUSB", 0x2343: "VFMSUB231SD", 0x202c: "PMAXUD", 0x108a: "FXSAVE",
0x585: "FISTTP", 0x1480: "VCMPGEPD", 0x248b: "BLENDPS", 0x1723: "VCMPLESD",
0x5ac: "FCMOVNBE", 0x2336: "VFMSUB231SS", 0x25c8: "VBLENDVPS", 0x25a7: "VMPSADBW",
0x19bf: "VPSUBUSW", 0x1719: "VCMPLTSD", 0x1ee2: "MOVNTDQA", 0x18cb: "SHUFPD",
0xd38: "SUBPD", 0xb2c: "SQRTPD", 0x953: "VMOVHPD", 0x6bc: "VMCALL", 0x20c5: "VFMADD132PD",
0x15b: "LEAVE", 0x18c3: "SHUFPS", 0x130e: "VCMPEQ_OSPS", 0x260b: "VPCMPESTRI",
0x1587: "VCMPLTSS", 0x25f4: "VPCMPESTRM", 0x20b8: "VFMADD132PS", 0x6a2: "LIDT",
0x49d: "F2XM1", 0x94a: "VMOVHPS", 0x1f8d: "PMOVZXDQ", 0x100f: "VZEROUPPER",
0xb24: "SQRTPS", 0xbda: "VANDNPS", 0x1963: "VPADDQ", 0x4dd: "FPREM", 0x1c45: "VPADDW",
0x23d1: "AESENC", 0x24c4: "PALIGNR", 0x1fb5: "PMINSB", 0xe8e: "PCMPGTW", 0x36c: "SHLD",
0x14f: "LDS", 0x1c36: "VPADDB", 0x708: "VMRUN", 0xbe3: "VANDNPD", 0x190: "XLAT",
0xd4: "XCHG", 0x4d4: "FINCSTP", 0x1985: "MOVDQ2Q", 0x1b01: "PMINSW", 0x6a8: "SMSW",
0x1d52: "VPSIGNB", 0x10c8: "XRSTOR", 0x24a7: "VBLENDPD", 0xc0: "JGE", 0x1352: "VCMPNLT_UQPS",
0x175b: "VCMPORDSD", 0x2494: "VBLENDPS", 0x45e: "FTST", 0x1a83: "CVTTPD2DQ",
0x15c9: "VCMPORDSS", 0x14e4: "VCMPNLT_UQPD", 0x2174: "VFNMSUB132SS", 0x10d0: "XRSTOR64",
0x29: "AND", 0xb7a: "VRSQRTPS", 0x1100: "CLFLUSH", 0x1cb8: "PSHUFB", 0x437: "FLDENV",
0xda: "MOV", 0xf99: "PSHUFD", 0xc5: "JLE", 0x5c5: "FEDISI", 0x700: "VMFUNC",
0xe97: "VPCMPGTW", 0x7f8: "PFCMPEQ", 0x1692: "VCMPORD_SSS", 0xf91: "PSHUFW",
0x24df: "VPEXTRB", 0x1aae: "VCVTDQ2PD", 0xf68: "VMOVQ", 0x478: "FLDL2E", 0x24f8: "VPEXTRD",
0x1d1d: "VPHSUBW", 0x2270: "VFNMSUB213PS", 0x21dd: "VFMADD213PD", 0x728: "STGI",
0x4b2: "FPATAN", 0x2501: "VPEXTRQ", 0x42c: "FST", 0x168: "INT 3", 0x58d: "FIST",
0x26c1: "VMCLEAR", 0x1e6a: "PMOVSXBQ", 0x42: "AAA", 0x1d2e: "VPHSUBD", 0xa30: "CVTTPS2PI",
0x1144: "CMPNEQPS", 0x1554: "VCMPGE_OQPD", 0x1b5d: "LDDQU", 0xb68: "RSQRTPS",
0xc48: "VADDPD", 0x7a7: "PFRCP", 0xcb0: "CVTSS2SD", 0x2182: "VFNMSUB132SD",
0x627: "FDIVRP", 0x636: "FBLD", 0x361: "CPUID", 0x251: "RDTSC", 0x24ba: "VPBLENDW",
0xd1a: "VCVTPS2DQ", 0x1b17: "VPOR", 0xc40: "VADDPS", 0x76a: "PI2FW", 0xd6d: "MINPS",
0x17c4: "VCMPEQ_OSSD", 0x1ba2: "VPMULUDQ", 0xdfa: "MAXSD", 0x2045: "VPMULLD",
0x54d: "FIDIVR", 0xac4: "VUCOMISS", 0x88f: "MOVDDUP", 0x1cc0: "VPSHUFB", 0x1d37: "PHSUBSW",
0x2639: "VPCMPISTRI", 0xdf3: "MAXSS", 0x1a2a: "VPAVGB", 0x16c8: "VCMPFALSE_OSSS",
0xd74: "MINPD", 0x4e4: "FYL2XP1", 0xace: "VUCOMISD", 0x2396: "VFNMSUB231PD",
0x183e: "VCMPNGE_UQSD", 0xc39: "ADDSD", 0x6d8: "VMXOFF", 0x194d: "PSRLQ", 0x1284: "VCMPNEQPS",
0x192f: "PSRLW", 0x1a41: "PSRAD", 0x696: "SIDT", 0xe66: "PACKSSWB", 0x10b0: "XSAVE",
0x1416: "VCMPNEQPD", 0xfa: "CDQ", 0xc32: "ADDSS", 0x16ac: "VCMPNGE_UQSS", 0x242c: "CRC32",
0x23c8: "VAESIMC", 0x1ff9: "PMAXSB", 0x2515: "VEXTRACTPS", 0x1808: "VCMPNLT_UQSD",
0x1bfa: "VPSUBB", 0x1f82: "VPMOVZXWQ", 0x13b4: "VCMPNEQ_OSPS", 0xa0a: "MOVNTSS",
0x252e: "VEXTRACTF128", 0x1b1d: "PADDSB", 0x75: "IMUL", 0x3db: "RCR", 0x14c7: "VCMPUNORD_SPD",
0x3d6: "RCL", 0xa13: "MOVNTSD", 0x1546: "VCMPNEQ_OSPD", 0x1676: "VCMPNLT_UQSS",
0xd46: "SUBSD", 0x13f: "SCAS", 0x25b1: "PCLMULQDQ", 0x7ae: "PFRSQRT", 0x2562: "PINSRD",
0x618: "FSUBRP", 0x5b: "PUSHA", 0x1a0b: "VPMAXUB", 0x1138: "CMPUNORDPS", 0x2034: "VPMAXUD",
0x458: "FABS", 0x1e74: "VPMOVSXBQ", 0x1494: "VCMPTRUEPD", 0x23e: "FEMMS", 0x1632: "VCMPEQ_OSSS",
0x21f7: "VFMADD213SD", 0x1e5f: "VPMOVSXBD", 0x1187: "CMPUNORDPD", 0x18fc: "VMPTRST",
0x18f0: "CMPXCHG16B", 0x1302: "VCMPTRUEPS", 0x12c8: "VCMPNGTPS", 0x1c7c: "FNCLEX",
0x1231: "CMPNEQSD", 0x1766: "VCMPEQ_UQSD", 0x56e: "FCMOVU", 0x102d: "EXTRQ",
0x2591: "DPPD", 0x2e2: "CMOVGE", 0x253c: "PINSRB", 0x15d4: "VCMPEQ_UQSS", 0x1d09: "VPMADDUBSW",
0x11e2: "CMPNEQSS", 0x22f5: "VFMADD231PD", 0x50e: "FSIN", 0x1bf: "IN", 0x55d: "FCMOVE",
0x43f: "FLDCW", 0x2584: "DPPS", 0x555: "FCMOVB", 0x1936: "VPSRLW", 0x10c0: "LFENCE",
0xa92: "CVTSD2SI", 0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x1954: "VPSRLQ", 0x609: "FMULP",
0x9b1: "VMOVAPD", 0x164c: "VCMPLE_OQSS", 0x2c4: "CMOVNS", 0x5a3: "FCMOVNE",
0x288: "CMOVNO", 0x1a7a: "VPMULHW", 0x1945: "VPSRLD", 0xa74: "CVTPS2PI", 0x1cda: "PHADDD",
0xc9c: "CVTPS2PD", 0x1e29: "VPABSW", 0x17de: "VCMPLE_OQSD", 0x9a8: "VMOVAPS",
0x1c09: "VPSUBW", 0x812: "PMULHRW", 0x998: "MOVAPS", 0x7a0: "PFMIN", 0xf55: "MOVD",
0x926: "MOVHPS", 0xc60: "MULPS", 0x1263: "VCMPLTPS", 0x368: "BT", 0x9a0: "MOVAPD",
0x1388: "VCMPNGE_UQPS", 0x1b8: "JRCXZ", 0xc67: "MULPD", 0x127: "MOVS", 0x6b4: "INVLPG",
0xf5b: "MOVQ", 0xd91: "VMINPD", 0x1e31: "PABSD", 0x11b: "SAHF", 0x13dc: "VCMPTRUE_USPS",
0x771: "PI2FD", 0x1e13: "PABSB", 0x1a1b: "VPANDN", 0xe5a: "VPUNPCKLDQ", 0x62f: "FDIVP",
0x1c20: "PSUBQ", 0x420: "FDIVR", 0x41a: "FDIV", 0x156e: "VCMPTRUE_USPD", 0x755: "PREFETCH",
0x1009: "EMMS", 0xd89: "VMINPS", 0x22e8: "VFMADD231PS", 0x227e: "VFNMSUB213PD",
0xa88: "CVTSS2SI", 0x92e: "MOVHPD", 0x29f: "CMOVZ", 0x1a57: "VPAVGW", 0xff: "CQO",
0x1c18: "VPSUBD", 0x2cc: "CMOVP", 0x157d: "VCMPEQSS", 0x2bd: "CMOVS", 0x1e55: "PMOVSXBD",
0x246e: "VROUNDSS", 0x1c27: "VPSUBQ", 0x2db: "CMOVL", 0x190f: "ADDSUBPS", 0x281: "CMOVO",
0x2b6: "CMOVA", 0x290: "CMOVB", 0xec9: "PUNPCKHBW", 0x262e: "PCMPISTRI", 0x2f2: "CMOVG",
0x1998: "VPMOVMSKB", 0x240c: "AESDECLAST", 0x834: "MOVUPD", 0x20a8: "VFMSUBADD132PD",
0x1bc7: "VPSADBW", 0x245b: "VROUNDPD", 0x6ae: "LMSW", 0x2067: "INVEPT", 0x39f: "MOVZX",
0xbac: "ANDPS", 0x2098: "VFMSUBADD132PS", 0x82c: "MOVUPS", 0x161c: "VCMPGTSS",
0x1a5f: "PMULHUW", 0x2597: "VDPPD", 0x24e8: "PEXTRD", 0x15f7: "VCMPFALSESS",
0x1b: "OR", 0x18ba: "VPEXTRW", 0x1ae7: "VPSUBSB", 0x109c: "FXRSTOR", 0x21d: "CLTS",
0x184c: "VCMPNGT_UQSD", 0x15ec: "VCMPNGTSS", 0x5e4: "FRSTOR", 0x1789: "VCMPFALSESD",
0x48f: "FLDLN2", 0x2521: "VINSERTF128", 0x1af8: "VPSUBSW", 0x1b99: "PMULUDQ",
0x56: "DEC", 0x13a4: "VCMPFALSE_OSPS", 0x427: "FLD", 0x1f97: "VPMOVZXDQ", 0x2465: "ROUNDSS",
0x9e2: "VCVTSI2SS", 0x18b2: "PEXTRW", 0x3cc: "ROL", 0x20df: "VFMADD132SD",
0x117e: "CMPLEPD", 0xce5: "VCVTSD2SS", 0x5fa: "FUCOMP", 0x1ce: "JMP", 0x170f: "VCMPEQSD",
0xcf0: "CVTDQ2PS", 0x16f3: "VCMPGT_OQSS", 0x5d5: "FUCOMI", 0x1116: "LZCNT",
0xb9c: "VRCPPS", 0x1a03: "PMAXUB", 0x1ce2: "VPHADDD", 0x9ed: "VCVTSI2SD", 0x1885: "VCMPGT_OQSD",
0x3d1: "ROR", 0x22b: "INVD", 0xaa7: "VCVTSD2SI", 0x23fb: "AESDEC", 0x1245: "CMPNLESD",
0x354: "SETLE", 0x22c8: "VFMSUBADD231PS", 0x2350: "VFNMADD231PS", 0x10b7: "XSAVE64",
0xee0: "PUNPCKHWD", 0x1e89: "VPMOVSXWD", 0xca6: "CVTPD2PS", 0x898: "VMOVHLPS",
0x22d8: "VFMSUBADD231PD", 0xa7e: "CVTPD2PI", 0x11f6: "CMPNLESS", 0x1ebe: "PMULDQ",
0x1e9e: "VPMOVSXWQ", 0x1745: "VCMPNLTSD", 0x235e: "VFNMADD231PD", 0x1cb1: "FSTSW",
0x74d: "RDTSCP", 0x10da: "MFENCE", 0x20d2: "VFMADD132SS", 0x1fe8: "PMINUD",
0x5bf: "FENI", 0x68: "BOUND", 0x2448: "VROUNDPS", 0xfaa: "PSHUFLW", 0xc8c: "VMULSS",
0x185a: "VCMPFALSE_OSSD", 0xd0f: "VCVTDQ2PS", 0x1591: "VCMPLESS", 0x44c: "FNOP",
0x114e: "CMPNLTPS", 0x128f: "VCMPNLTPS", 0x487: "FLDLG2", 0x223: "SYSRET",
0x1c75: "FSTCW", 0x221e: "VFMSUB213SS", 0x734: "SKINIT", 0xbc2: "VANDPD", 0x497: "FLDZ",
0x33: "SUB", 0x1cd1: "VPHADDW", 0x659: "NEG", 0x1fd7: "PMINUW", 0xdec: "MAXPD",
0x136e: "VCMPORD_SPS", 0x133: "STOS", 0x23b2: "VFNMSUB231SD", 0x172d: "VCMPUNORDSD",
0x823: "PAVGUSB", 0x1500: "VCMPORD_SPD", 0xde5: "MAXPS", 0x19c9: "PMINUB",
0x1be6: "VMASKMOVDQU", 0x63c: "FBSTP", 0x18a1: "PINSRW", 0x1f6d: "VPMOVZXWD",
0x1fdf: "VPMINUW", 0x1816: "VCMPNLE_UQSD", 0x18a: "SALC", 0x24d7: "PEXTRB",
0x8dd: "VUNPCKLPS", 0x1684: "VCMPNLE_UQSS", 0xf6f: "MOVDQA", 0x15b3: "VCMPNLTSS",
0x1b8a: "PSLLQ", 0xa1c: "VMOVNTPS", 0x1ff0: "VPMINUD", 0x967: "PREFETCHNTA",
0x8e8: "VUNPCKLPD", 0x2481: "VROUNDSD", 0x2656: "VAESKEYGENASSIST", 0x1af0: "PSUBSW",
0x1773: "VCMPNGESD", 0x1c5c: "FNSTENV", 0x1ca9: "FNSTSW", 0x1193: "CMPNEQPD",
0x1a50: "PAVGW", 0xa01: "MOVNTPD", 0x150d: "VCMPEQ_USPD", 0x5cd: "FSETPM",
0x1dc4: "BLENDVPS", 0x21a0: "VFMADDSUB213PD", 0xb: "ADD", 0x15e1: "VCMPNGESS",
0x1f: "ADC", 0x1adf: "PSUBSB", 0x1dce: "BLENDVPD", 0xed4: "VPUNPCKHBW", 0x25f: "RDPMC",
0x9f8: "MOVNTPS", 0xbca: "ANDNPS", 0x13f5: "VCMPLTPD", 0x1a23: "PAVGB", 0xdf: "LEA",
0x1aa2: "VCVTTPD2DQ", 0xe84: "VPCMPGTB", 0xeaa: "VPCMPGTD", 0x46a: "FLD1",
0x1bb5: "VPMADDWD", 0x17eb: "VCMPUNORD_SSD", 0x14a: "LES", 0x313: "SETZ", 0x1fab: "VPCMPGTQ",
0xc94: "VMULSD", 0x21d0: "VFMADD213PS", 0x15be: "VCMPNLESS", 0x86c: "MOVHLPS",
0x205a: "VPHMINPOSUW", 0x1e38: "VPABSD", 0x1a32: "PSRAW", 0x7be: "PFADD", 0x2088: "VFMADDSUB132PD",
0xae0: "COMISD", 0x13c2: "VCMPGE_OQPS", 0xe11: "VMAXSS", 0x1225: "CMPUNORDSD",
0x4f4: "FSINCOS", 0xad8: "COMISS", 0x2078: "VFMADDSUB132PS", 0xb8e: "RCPPS",
0x212e: "VFNMADD132PD", 0x446: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcc4: "VCVTPS2PD",
0x1bac: "PMADDWD", 0xbb3: "ANDPD", 0x1328: "VCMPLE_OQPS", 0x177e: "VCMPNGTSD",
0x2388: "VFNMSUB231PS", 0x643: "FUCOMIP", 0xc7c: "VMULPS", 0x2120: "VFNMADD132PS",
0x38: "DAS", 0x14ba: "VCMPLE_OQPD", 0x17a: "IRET", 0x3c5: "BSWAP", 0xe21: "PUNPCKLBW",
0x201b: "PMAXUW", 0x2622: "VPCMPISTRM", 0x1b6c: "PSLLW", 0x1659: "VCMPUNORD_SSS",
0x2238: "VFNMADD213PS", 0xa68: "VCVTTSD2SI", 0x2329: "VFMSUB231PD", 0x1396: "VCMPNGT_UQPS",
0x1c6d: "FNSTCW", 0x2478: "ROUNDSD", 0x11a7: "CMPNLEPD", 0x24f0: "PEXTRQ",
0x1a72: "PMULHW", 0x1cf4: "VPHADDSW", 0x593: "FISTP", 0x1f78: "PMOVZXWQ", 0xccf: "VCVTPD2PS",
0x1700: "VCMPTRUE_USSS", 0xc58: "VADDSD", 0x1dba: "PBLENDVB", 0x6ce: "VMRESUME",
0xabb: "UCOMISD", 0x1f63: "PMOVZXWD", 0xa3b: "CVTTPD2PI", 0xab2: "UCOMISS",
0xe70: "VPACKSSWB", 0xc50: "VADDSS", 0xfa1: "PSHUFHW", 0x1892: "VCMPTRUE_USSD",
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
