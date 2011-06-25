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

Mnemonics = {0x66e: "SLDT", 0x62: "POPA", 0x8eb: "UNPCKHPS", 0x115: "POPF", 0x117d: "CMPLTSS",
0x84a: "VMOVSD", 0x786: "PFPNACC", 0xb11: "VMOVMSKPD", 0x734: "INVLPGA", 0x8f5: "UNPCKHPD",
0x270: "SYSEXIT", 0x7af: "PFSUB", 0x11cc: "CMPLTSD", 0x1535: "VPMULHUW", 0x842: "VMOVSS",
0x6f: "ARPL", 0x52f: "FICOMP", 0x162: "RETF", 0x452: "FCHS", 0x10e8: "CMPLEPS",
0xeef: "PUNPCKHDQ", 0x5f3: "FUCOM", 0x125e: "VCMPORDPS", 0x1483: "PSUBUSW",
0x1afb: "PMAXUD", 0x18e9: "VPABSB", 0x24a: "WRMSR", 0x1d87: "VFMADDSUB231PD",
0x7c6: "PFMAX", 0x1d15: "VFNMADD213PD", 0x3bd: "MOVNTI", 0x7bd: "PFCMPGT",
0x1e3b: "VFNMADD231SS", 0x1fa7: "PEXTRB", 0xb94: "VRCPSS", 0x1ce0: "VFMSUB213PD",
0x17c1: "VPHADDSW", 0x2147: "VPSLLDQ", 0x78f: "PFCMPGE", 0x155b: "CVTDQ2PD",
0x11d5: "CMPLESD", 0xae: "JNS", 0xdd5: "VDIVSD", 0xb7: "JNP", 0x1093: "XAVE",
0x1a1d: "PMOVZXBQ", 0x9c: "JNZ", 0x5dd: "FCOMI", 0xee3: "VPUNPCKHWD", 0x1a08: "PMOVZXBD",
0x15a2: "VMOVNTDQ", 0x194e: "PMOVSXWD", 0x10c2: "POPCNT", 0x8a: "JNO", 0x1767: "FNSAVE",
0x1a5: "LOOP", 0xb06: "VMOVMSKPS", 0x470: "FLDL2T", 0x12d: "CMPS", 0x40d: "FSUB",
0xda1: "DIVPS", 0x17f3: "PHSUBD", 0x1174: "CMPEQSS", 0x1e7: "CMC", 0xcfc: "CVTTPS2DQ",
0xda8: "DIVPD", 0xf59: "VMOVD", 0x104: "CALL FAR", 0x184a: "PMULHRSW", 0x1854: "VPMULHRSW",
0x17e2: "PHSUBW", 0x11c3: "CMPEQSD", 0x3b7: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x1057: "VHADDPS", 0x1b3e: "INVVPID", 0x20f: "LSL", 0x104e: "VHADDPD",
0x38b: "LSS", 0x1bc8: "VFMSUB132PD", 0x121: "LAHF", 0x7e9: "PFACC", 0x800: "PFRCPIT2",
0xe24: "VPUNPCKLBW", 0x7cd: "PFRCPIT1", 0x1a71: "PCMPGTQ", 0x4a4: "FYL2X",
0x140b: "PSRLD", 0x10b1: "SFENCE", 0xcf2: "CVTPS2DQ", 0x1f80: "PBLENDW", 0x1c7f: "VFMSUBADD213PS",
0xe73: "PCMPGTB", 0xe99: "PCMPGTD", 0x1ea8: "VAESENC", 0x954: "VMOVSHDUP",
0x2065: "MPSADBW", 0x1ed2: "VAESDEC", 0x707: "VMMCALL", 0x102c: "INSERTQ",
0x1d23: "VFNMADD213SS", 0x9bc: "CVTPI2PD", 0x16f: "INT", 0x185f: "VPERMILPS",
0x1e2: "HLT", 0x1b1d: "PHMINPOSUW", 0x5b6: "FCMOVNU", 0x7b: "INS", 0x64c: "FCOMIP",
0x9b2: "CVTPI2PS", 0x1d31: "VFNMADD213SD", 0xeac: "PACKUSWB", 0xe4: "CBW",
0x718: "VMSAVE", 0x10e: "PUSHF", 0x654: "NOT", 0x59a: "FCMOVNB", 0x245: "NOP",
0x4ed: "FSQRT", 0x186a: "VPERMILPD", 0x51: "INC", 0x239: "UD2", 0xfe4: "VPCMPEQW",
0x20dd: "PCMPISTRM", 0x19a7: "VPCMPEQQ", 0x1111: "CMPNLEPS", 0x1287: "VCMPUNORDPD",
0x602: "FADDP", 0x145: "RET", 0xff7: "VPCMPEQD", 0x200b: "VPINSRB", 0xfd1: "VPCMPEQB",
0x13d2: "ADDSUBPD", 0x1d77: "VFMADDSUB231PS", 0x14f7: "VPAVGB", 0x1828: "PSIGNW",
0x1982: "VPMOVSXDQ", 0x1ae1: "VPMAXSD", 0x35b: "SETG", 0x1ad0: "VPMAXSB", 0x327: "SETA",
0x306: "SETB", 0x2163: "STMXCSR", 0x347: "SETL", 0x1bbb: "VFMSUB132PS", 0x2f9: "SETO",
0xbca: "ANDNPD", 0x10ca: "BSR", 0x8b7: "VMOVDDUP", 0x1614: "VPMAXSW", 0x1839: "PSIGND",
0x33a: "SETP", 0x1817: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x12de: "VCMPUNORDSS",
0x3ab: "BSF", 0x2188: "VMXON", 0xbb2: "VANDPS", 0x6f8: "XSETBV", 0x1c3: "OUT",
0x67f: "LTR", 0x2039: "VPINSRD", 0xa54: "VCVTTSS2SI", 0x2136: "VPSRLDQ", 0x4cb: "FDECSTP",
0x212e: "PSRLDQ", 0x213f: "PSLLDQ", 0x514: "FCOS", 0x4ba: "FXTRACT", 0x19bb: "VMOVNTDQA",
0x3fa: "FMUL", 0x610: "FCOMPP", 0x777: "PF2ID", 0xf5: "CWD", 0x2ea: "CMOVLE",
0xfb4: "VPSHUFHW", 0x12c0: "VCMPEQSS", 0x17b8: "PHADDSW", 0x770: "PF2IW", 0xa1e: "VMOVNTPD",
0x406: "FCOMP", 0x8c1: "UNPCKLPS", 0x16a7: "MASKMOVDQU", 0x565: "FCMOVBE",
0xe11: "VMAXSD", 0x129f: "VCMPNLTPD", 0x984: "PREFETCHT2", 0x978: "PREFETCHT1",
0x96c: "PREFETCHT0", 0x8cb: "UNPCKLPD", 0xa3e: "CVTTSS2SI", 0x663: "DIV", 0x1978: "PMOVSXDQ",
0x1a9d: "VPMINSD", 0xef: "CDQE", 0x216c: "VSTMXCSR", 0x53e: "FISUBR", 0x1a8c: "VPMINSB",
0x1cd3: "VFMSUB213PS", 0x1186: "CMPLESS", 0x15d6: "VPMINSW", 0x1732: "FSTENV",
0x18ae: "VPTEST", 0x537: "FISUB", 0x205: "STD", 0xf10: "VPACKSSDW", 0x3d: "XOR",
0xc7c: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x2150: "LDMXCSR", 0x112e: "CMPLTPD",
0xbe4: "ORPS", 0x19d0: "VPACKUSDW", 0x620: "FSUBP", 0x674: "STR", 0x413: "FSUBR",
0x10df: "CMPLTPS", 0x1dde: "VFMADD231SD", 0x219d: "PAUSE", 0x1565: "CVTPD2DQ",
0x372: "RSM", 0xb45: "VSQRTSD", 0xbf0: "VORPS", 0x1c5f: "VFMADDSUB213PS", 0x1ea0: "AESENC",
0x8ff: "VUNPCKHPS", 0x17cb: "PMADDUBSW", 0x1640: "VPSLLW", 0x169d: "MASKMOVQ",
0x1c8: "CALL", 0xb3c: "VSQRTSS", 0x14b4: "PADDUSB", 0x101d: "VMREAD", 0x90a: "VUNPCKHPD",
0xd45: "VSUBPS", 0xcbc: "VCVTSS2SD", 0x1f89: "VPBLENDVW", 0x1ee7: "VAESDECLAST",
0x1068: "HSUBPS", 0xa94: "VCVTSS2SI", 0x20a5: "VPBLENDVB", 0x19b1: "MOVNTDQA",
0x57f: "FILD", 0xae0: "VCOMISS", 0x1060: "HSUBPD", 0x1e73: "VFNMSUB231SS",
0x1515: "VPSRAD", 0x1253: "VCMPNLEPS", 0x3ea: "SAL", 0x214: "SYSCALL", 0xb72: "VRSQRTSS",
0x2042: "VPINSRQ", 0xfab: "VPSHUFD", 0x190f: "PMOVSXBW", 0x1506: "VPSRAW",
0x12aa: "VCMPNLEPD", 0x3f4: "FADD", 0x3ef: "SAR", 0x1591: "MOVNTQ", 0x210b: "AESKEYGENASSIST",
0xf06: "PACKSSDW", 0x1cb9: "VFMADD213SS", 0xf77: "VMOVDQA", 0x8ac: "VMOVSLDUP",
0x4fd: "FRNDINT", 0x1438: "PMULLW", 0xdb6: "DIVSD", 0xaf2: "MOVMSKPS", 0x1af2: "VPMAXUW",
0xdc5: "VDIVPD", 0x1919: "VPMOVSXBW", 0x1963: "PMOVSXWQ", 0x1b0c: "PMULLD",
0xf80: "VMOVDQU", 0x297: "CMOVAE", 0xdbd: "VDIVPS", 0x93: "JAE", 0xafc: "MOVMSKPD",
0xdaf: "DIVSS", 0x1e97: "VAESIMC", 0x199e: "PCMPEQQ", 0xfbe: "VPSHUFLW", 0xfdb: "PCMPEQW",
0x2159: "VLDMXCSR", 0x1bd5: "VFMSUB132SS", 0x116a: "CMPORDPD", 0xb8d: "RCPSS",
0x164f: "VPSLLD", 0x668: "IDIV", 0x12b5: "VCMPORDPD", 0xfc8: "PCMPEQB", 0xfee: "PCMPEQD",
0x165e: "VPSLLQ", 0x1a27: "VPMOVZXBQ", 0x1c8f: "VFMSUBADD213PD", 0x209a: "VBLENDVPD",
0x111b: "CMPORDPS", 0xf1b: "PUNPCKLQDQ", 0x14ad: "VPAND", 0x179e: "VPHADDW",
0x103e: "HADDPD", 0x13f1: "VADDSUBPS", 0x13a9: "VSHUFPD", 0xd5d: "VSUBSD",
0xb4e: "VSQRTPS", 0x92e: "MOVSHDUP", 0x1e49: "VFNMADD231SD", 0x6c4: "VMLAUNCH",
0x19e7: "VMASKMOVPD", 0x1046: "HADDPS", 0xe30: "PUNPCKLWD", 0xb57: "VSQRTPD",
0xd55: "VSUBSS", 0x13a0: "VSHUFPS", 0x12eb: "VCMPNEQSS", 0x1631: "VLDDQU",
0x15fb: "PADDSW", 0xbea: "ORPD", 0x1a95: "PMINSD", 0x4ab: "FPTAN", 0x546: "FIDIV",
0x161d: "PXOR", 0x2176: "VMPTRLD", 0x1deb: "VFMSUB231PS", 0x1342: "VCMPNEQSD",
0x1995: "VPMULDQ", 0x196: "LOOPNZ", 0x1230: "VCMPUNORDPS", 0x3e5: "SHR", 0x37c: "SHRD",
0x6e0: "MONITOR", 0x1875: "VPTESTPS", 0x1eb1: "AESENCLAST", 0x83b: "MOVSD",
0x1376: "VPINSRW", 0x710: "VMLOAD", 0x915: "MOVLHPS", 0x8a3: "VMOVLPD", 0x1449: "MOVQ2DQ",
0xb2c: "SQRTSS", 0x2051: "VDPPS", 0xd37: "SUBSS", 0x3b0: "MOVSX", 0x938: "VMOVLHPS",
0x89a: "VMOVLPS", 0xefa: "VPUNPCKHDQ", 0x1586: "VCVTPD2DQ", 0x3e0: "SHL", 0x834: "MOVSS",
0x2031: "PINSRQ", 0x77e: "PFNACC", 0xf6f: "MOVDQU", 0x80: "OUTS", 0x16c0: "PSUBB",
0x377: "BTS", 0x390: "BTR", 0x690: "SGDT", 0x1dd1: "VFMADD231SS", 0x506: "FSCALE",
0x16cf: "PSUBW", 0x1156: "CMPNLTPD", 0x19c6: "PACKUSDW", 0x20a: "LAR", 0x3a6: "BTC",
0x1c19: "VFNMADD132SD", 0x1fd1: "EXTRACTPS", 0x19fd: "VPMOVZXBW", 0x1be2: "VFMSUB132SD",
0x1e8f: "AESIMC", 0x400: "FCOM", 0x1a12: "VPMOVZXBD", 0x13e6: "VADDSUBPD",
0x11b9: "CMPORDSS", 0x231: "WBINVD", 0x14a7: "PAND", 0x1f9d: "VPALIGNR", 0x1208: "CMPORDSD",
0x1623: "VPXOR", 0xa1: "JBE", 0x464: "FXAM", 0x65e: "MUL", 0x176f: "FSAVE",
0x1603: "VPADDSW", 0x160c: "PMAXSW", 0x201e: "VINSERTPS", 0x1269: "VCMPEQPD",
0x5ec: "FFREE", 0x19db: "VMASKMOVPS", 0x13b2: "CMPXCHG8B", 0x1ad9: "PMAXSD",
0x187f: "VPTESTPD", 0x15f2: "VPADDSB", 0x10: "PUSH", 0x2083: "VPCLMULQDQ",
0x1212: "VCMPEQPS", 0x7d7: "PFRSQIT1", 0x1f0e: "ROUNDPS", 0x2ff: "SETNO", 0x6f0: "XGETBV",
0x1f21: "ROUNDPD", 0x16fc: "PADDB", 0x4c3: "FPREM1", 0x200: "CLD", 0x521: "FIMUL",
0xc05: "XORPD", 0x1ec: "CLC", 0x431: "FSTP", 0x1f6d: "BLENDPD", 0x14c7: "PADDUSW",
0x1758: "FNINIT", 0x319: "SETNZ", 0x1429: "PADDQ", 0xbfe: "XORPS", 0x333: "SETNS",
0x51a: "FIADD", 0x340: "SETNP", 0xf40: "VPUNPCKHQDQ", 0xd29: "SUBPS", 0x11f4: "CMPNLTSD",
0x679: "LLDT", 0x1cfa: "VFMSUB213SD", 0x18a7: "PTEST", 0x1c35: "VFNMSUB132PD",
0x279: "GETSEC", 0x1841: "VPSIGND", 0x1ab: "JCXZ", 0x11a5: "CMPNLTSS", 0x34d: "SETGE",
0x10d6: "CMPEQPS", 0x168c: "PSADBW", 0x2195: "MOVSXD", 0x1c27: "VFNMSUB132PS",
0x185: "AAD", 0x1ebd: "VAESENCLAST", 0xf34: "PUNPCKHQDQ", 0x875: "MOVLPD",
0x14bd: "VPADDUSW", 0x180: "AAM", 0xf27: "VPUNPCKLQDQ", 0xd73: "MINSS", 0x171a: "PADDD",
0xe3b: "VPUNPCKLWD", 0x86d: "MOVLPS", 0x726: "CLGI", 0x4c: "AAS", 0x139: "LODS",
0x2d3: "CMOVNP", 0xd7a: "MINSD", 0x1f6: "CLI", 0xa49: "CVTTSD2SI", 0x528: "FICOM",
0x19f3: "PMOVZXBW", 0xc23: "ADDPD", 0x757: "PREFETCHW", 0xc14: "VXORPD", 0x15df: "POR",
0x16: "POP", 0x1f02: "VPERM2F128", 0x19e: "LOOPZ", 0x1599: "MOVNTDQ", 0x1dc: "INT1",
0x382: "CMPXCHG", 0x18d2: "VBROADCASTF128", 0x17d6: "VPMADDUBSW", 0x1796: "PHADDW",
0xc0c: "VXORPS", 0xc1c: "ADDPS", 0x7f9: "PFMUL", 0x69c: "LGDT", 0x684: "VERR",
0x68a: "VERW", 0x1070: "VHSUBPD", 0x852: "VMOVUPS", 0x174: "INTO", 0x1751: "FCLEX",
0x1079: "VHSUBPS", 0xcb2: "CVTSD2SS", 0x480: "FLDPI", 0x18f1: "PABSW", 0xe01: "VMAXPD",
0x1d3: "JMP FAR", 0xeb6: "VPACKUSWB", 0x576: "FUCOMPP", 0x85b: "VMOVUPD", 0x813: "PSWAPD",
0x170b: "PADDW", 0x1648: "PSLLD", 0x73d: "SWAPGS", 0x87d: "MOVSLDUP", 0x9c6: "CVTSI2SS",
0x118f: "CMPUNORDSS", 0xd1d: "VCVTTPS2DQ", 0xb34: "SQRTSD", 0x16de: "PSUBD",
0xce: "TEST", 0x39a: "LGS", 0x266: "SYSENTER", 0x9d0: "CVTSI2SD", 0x1358: "VCMPNLESD",
0x1c0b: "VFNMADD132SS", 0x98: "JZ", 0xdcd: "VDIVSS", 0xbf7: "VORPD", 0xb3: "JP",
0xaa: "JS", 0xbc: "JL", 0xb69: "RSQRTSS", 0x86: "JO", 0xdf9: "VMAXPS", 0x1470: "PSUBUSB",
0xca: "JG", 0x18b6: "VBROADCASTSS", 0xa6: "JA", 0x8f: "JB", 0xe9: "CWDE", 0x127d: "VCMPLEPD",
0x1035: "VMWRITE", 0x1226: "VCMPLEPS", 0x145b: "PMOVMSKB", 0x2014: "INSERTPS",
0x20c7: "PCMPESTRI", 0x218f: "WAIT", 0x18c4: "VBROADCASTSD", 0x20b0: "PCMPESTRM",
0xe47: "PUNPCKLDQ", 0xc66: "MULSS", 0xd4d: "VSUBPD", 0x1125: "CMPEQPD", 0xae9: "VCOMISD",
0xd91: "VMINSS", 0x1721: "VPADDD", 0x258: "RDMSR", 0x1830: "VPSIGNW", 0x1b1: "JECXZ",
0xc6d: "MULSD", 0x154: "ENTER", 0x1ef4: "MOVBE", 0x1013: "VZEROALL", 0xd99: "VMINSD",
0x7e1: "PFSUBR", 0x1edb: "AESDECLAST", 0x1479: "VPSUBUSB", 0x1e12: "VFMSUB231SD",
0x1082: "FXSAVE", 0x585: "FISTTP", 0x14e1: "PANDN", 0x1f5a: "BLENDPS", 0x132b: "VCMPLESD",
0x5ac: "FCMOVNBE", 0x1e05: "VFMSUB231SS", 0x208f: "VBLENDVPS", 0x206e: "VMPSADBW",
0x148c: "VPSUBUSW", 0x1321: "VCMPLTSD", 0x1398: "SHUFPD", 0xd30: "SUBPD", 0xb24: "SQRTPD",
0x94b: "VMOVHPD", 0x6bc: "VMCALL", 0x1b94: "VFMADD132PD", 0x15b: "LEAVE", 0x1390: "SHUFPS",
0x12ca: "VCMPLTSS", 0x20bb: "VPCMPESTRM", 0x1b87: "VFMADD132PS", 0x6a2: "LIDT",
0x49d: "F2XM1", 0x942: "VMOVHPS", 0x1a5c: "PMOVZXDQ", 0x1007: "VZEROUPPER",
0xb1c: "SQRTPS", 0xbd2: "VANDNPS", 0x1430: "VPADDQ", 0x4dd: "FPREM", 0x1712: "VPADDW",
0x1f94: "PALIGNR", 0x1a84: "PMINSB", 0xe86: "PCMPGTW", 0x36c: "SHLD", 0x14f: "LDS",
0x1703: "VPADDB", 0x700: "VMRUN", 0xbdb: "VANDNPD", 0x190: "XLAT", 0xd4: "XCHG",
0x4d4: "FINCSTP", 0x1452: "MOVDQ2Q", 0x15ce: "PMINSW", 0x6a8: "SMSW", 0x181f: "VPSIGNB",
0x10a1: "XRSTOR", 0x1f76: "VBLENDPD", 0xc0: "JGE", 0x1363: "VCMPORDSD", 0x1f63: "VBLENDPS",
0x45e: "FTST", 0x1550: "CVTTPD2DQ", 0x130c: "VCMPORDSS", 0x20d2: "VCMPESTRI",
0x1c43: "VFNMSUB132SS", 0x29: "AND", 0xb7c: "VRSQRTPS", 0x10b9: "CLFLUSH",
0x1785: "PSHUFB", 0x437: "FLDENV", 0xda: "MOV", 0xf91: "PSHUFD", 0xc5: "JLE",
0x5c5: "FEDISI", 0xe8f: "VPCMPGTW", 0x7f0: "PFCMPEQ", 0xf89: "PSHUFW", 0x1faf: "VPEXTRB",
0x157b: "VCVTDQ2PD", 0xf60: "VMOVQ", 0x478: "FLDL2E", 0x1fc8: "VPEXTRD", 0x17ea: "VPHSUBW",
0x1d3f: "VFNMSUB213PS", 0x1cac: "VFMADD213PD", 0x720: "STGI", 0x4b2: "FPATAN",
0x42c: "FST", 0x168: "INT 3", 0x58d: "FIST", 0x217f: "VMCLEAR", 0x1939: "PMOVSXBQ",
0x42: "AAA", 0x17fb: "VPHSUBD", 0xa28: "CVTTPS2PI", 0x10fd: "CMPNEQPS", 0x162a: "LDDQU",
0xb60: "RSQRTPS", 0xc40: "VADDPD", 0x79f: "PFRCP", 0xca8: "CVTSS2SD", 0x1c51: "VFNMSUB132SD",
0x627: "FDIVRP", 0x636: "FBLD", 0x361: "CPUID", 0x251: "RDTSC", 0xd12: "VCVTPS2DQ",
0x15e4: "VPOR", 0xc38: "VADDPS", 0x762: "PI2FW", 0xd65: "MINPS", 0x166f: "VPMULUDQ",
0xdf2: "MAXSD", 0x1b14: "VPMULLD", 0x54d: "FIDIVR", 0xabc: "VUCOMISS", 0x887: "MOVDDUP",
0x178d: "VPSHUFB", 0x20ff: "VPCMPISTRI", 0xdeb: "MAXSS", 0x1440: "VPMULLW",
0xd6c: "MINPD", 0x4e4: "FYL2XP1", 0xac6: "VUCOMISD", 0x1e65: "VFNMSUB231PD",
0xc31: "ADDSD", 0x6d8: "VMXOFF", 0x141a: "PSRLQ", 0x123d: "VCMPNEQPS", 0x13fc: "PSRLW",
0x696: "SIDT", 0xe5e: "PACKSSWB", 0x1294: "VCMPNEQPD", 0xfa: "CDQ", 0xc2a: "ADDSS",
0x1d5b: "VFNMSUB213SS", 0x1efb: "CRC32", 0x1ac8: "PMAXSB", 0x1fdc: "VEXTRACTPS",
0x16c7: "VPSUBB", 0x1a51: "VPMOVZXWQ", 0xa02: "MOVNTSS", 0x1ff5: "VEXTRACTF128",
0x15ea: "PADDSB", 0x75: "IMUL", 0x3db: "RCR", 0x1760: "FINIT", 0x3d6: "RCL",
0xa0b: "MOVNTSD", 0xd3e: "SUBSD", 0x13f: "SCAS", 0x2078: "PCLMULQDQ", 0x7a6: "PFRSQRT",
0x2029: "PINSRD", 0x618: "FSUBRP", 0x5b: "PUSHA", 0x14d8: "VPMAXUB", 0x10f1: "CMPUNORDPS",
0x1b03: "VPMAXUD", 0x458: "FABS", 0x1943: "VPMOVSXBQ", 0x23e: "FEMMS", 0x1cc6: "VFMADD213SD",
0x192e: "VPMOVSXBD", 0x1140: "CMPUNORDPD", 0x13c9: "VMPTRST", 0x13bd: "CMPXCHG16B",
0x1749: "FNCLEX", 0x11ea: "CMPNEQSD", 0x56e: "FCMOVU", 0x1025: "EXTRQ", 0x2058: "DPPD",
0x2e2: "CMOVGE", 0x2003: "PINSRB", 0x1d69: "VFNMSUB213SD", 0x119b: "CMPNEQSS",
0x1dc4: "VFMADD231PD", 0x50e: "FSIN", 0x1bf: "IN", 0x55d: "FCMOVE", 0x43f: "FLDCW",
0x204b: "DPPS", 0x555: "FCMOVB", 0x1403: "VPSRLW", 0x1099: "LFENCE", 0xa8a: "CVTSD2SI",
0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x1421: "VPSRLQ", 0x609: "FMULP", 0x9a9: "VMOVAPD",
0x2c4: "CMOVNS", 0x5a3: "FCMOVNE", 0x288: "CMOVNO", 0x1547: "VPMULHW", 0x1412: "VPSRLD",
0xa6c: "CVTPS2PI", 0x17a7: "PHADDD", 0xc94: "CVTPS2PD", 0x18f8: "VPABSW", 0x9a0: "VMOVAPS",
0x16d6: "VPSUBW", 0x80a: "PMULHRW", 0x990: "MOVAPS", 0x798: "PFMIN", 0xf4d: "MOVD",
0x91e: "MOVHPS", 0xc58: "MULPS", 0x121c: "VCMPLTPS", 0x368: "BT", 0x998: "MOVAPD",
0x1b8: "JRCXZ", 0xc5f: "MULPD", 0x127: "MOVS", 0x6b4: "INVLPG", 0xf53: "MOVQ",
0xd89: "VMINPD", 0x1900: "PABSD", 0x11b: "SAHF", 0x1804: "PHSUBSW", 0x769: "PI2FD",
0x18e2: "PABSB", 0x14e8: "VPANDN", 0xe52: "VPUNPCKLDQ", 0x62f: "FDIVP", 0x16ed: "PSUBQ",
0x420: "FDIVR", 0x41a: "FDIV", 0x74d: "PREFETCH", 0x1001: "EMMS", 0xd81: "VMINPS",
0x1db7: "VFMADD231PS", 0x1d4d: "VFNMSUB213PD", 0xa80: "CVTSS2SI", 0x926: "MOVHPD",
0x29f: "CMOVZ", 0x1524: "VPAVGW", 0xff: "CQO", 0x16e5: "VPSUBD", 0x2cc: "CMOVP",
0x2bd: "CMOVS", 0x1924: "PMOVSXBD", 0x1f3d: "VROUNDSS", 0x16f4: "VPSUBQ", 0x2db: "CMOVL",
0x13dc: "ADDSUBPS", 0x281: "CMOVO", 0x2b6: "CMOVA", 0x290: "CMOVB", 0xec1: "PUNPCKHBW",
0x20f4: "PCMPISTRI", 0x2f2: "CMOVG", 0x1465: "VPMOVMSKB", 0x82c: "MOVUPD",
0x1b77: "VFMSUBADD132PD", 0x1694: "VPSADBW", 0x1f2a: "VROUNDPD", 0x6ae: "LMSW",
0x1b36: "INVEPT", 0x39f: "MOVZX", 0xba4: "ANDPS", 0x1b67: "VFMSUBADD132PS",
0x824: "MOVUPS", 0x152c: "PMULHUW", 0x205e: "VDPPD", 0x1fb8: "PEXTRD", 0x1b: "OR",
0x1387: "VPEXTRW", 0x15b4: "VPSUBSB", 0x108a: "FXRSTOR", 0x21d: "CLTS", 0x5e4: "FRSTOR",
0x1639: "PSLLW", 0x48f: "FLDLN2", 0x1fe8: "VINSERTF128", 0x15c5: "VPSUBSW",
0x1666: "PMULUDQ", 0x56: "DEC", 0x1679: "PMADDWD", 0x427: "FLD", 0x1a66: "VPMOVZXDQ",
0x9da: "VCVTSI2SS", 0x137f: "PEXTRW", 0x3cc: "ROL", 0x1bae: "VFMADD132SD",
0x1137: "CMPLEPD", 0xcc7: "VCVTSD2SS", 0x5fa: "FUCOMP", 0x1ce: "JMP", 0x1317: "VCMPEQSD",
0xce8: "CVTDQ2PS", 0x5d5: "FUCOMI", 0x10cf: "LZCNT", 0xb9c: "VRCPPS", 0x14d0: "PMAXUB",
0x17af: "VPHADDD", 0x9e5: "VCVTSI2SD", 0x3d1: "ROR", 0x22b: "INVD", 0xa9f: "VCVTSD2SI",
0x1eca: "AESDEC", 0x11fe: "CMPNLESD", 0x354: "SETLE", 0x1d97: "VFMSUBADD231PS",
0x1e1f: "VFNMADD231PS", 0xed8: "PUNPCKHWD", 0x1958: "VPMOVSXWD", 0xc9e: "CVTPD2PS",
0x890: "VMOVHLPS", 0x1da7: "VFMSUBADD231PD", 0xa76: "CVTPD2PI", 0x11af: "CMPNLESS",
0x198d: "PMULDQ", 0x196d: "VPMOVSXWQ", 0x134d: "VCMPNLTSD", 0x1e2d: "VFNMADD231PD",
0x177e: "FSTSW", 0x745: "RDTSCP", 0x10a9: "MFENCE", 0x1ba1: "VFMADD132SS",
0x1ab7: "PMINUD", 0x5bf: "FENI", 0x68: "BOUND", 0x1f17: "VROUNDPS", 0xfa2: "PSHUFLW",
0xc84: "VMULSS", 0xd07: "VCVTDQ2PS", 0x12d4: "VCMPLESS", 0x44c: "FNOP", 0x1107: "CMPNLTPS",
0x1248: "VCMPNLTPS", 0x487: "FLDLG2", 0x223: "SYSRET", 0x1742: "FSTCW", 0x1ced: "VFMSUB213SS",
0x72c: "SKINIT", 0xbba: "VANDPD", 0x497: "FLDZ", 0x33: "SUB", 0x180d: "VPHSUBSW",
0x659: "NEG", 0x1aa6: "PMINUW", 0xde4: "MAXPD", 0x133: "STOS", 0x1e81: "VFNMSUB231SD",
0x1335: "VCMPUNORDSD", 0x81b: "PAVGUSB", 0xddd: "MAXPS", 0x1496: "PMINUB",
0x16b3: "VMASKMOVDQU", 0x63c: "FBSTP", 0x136e: "PINSRW", 0x1a3c: "VPMOVZXWD",
0x1aae: "VPMINUW", 0x18a: "SALC", 0x8d5: "VUNPCKLPS", 0x149e: "VPMINUB", 0xf67: "MOVDQA",
0x12f6: "VCMPNLTSS", 0x1657: "PSLLQ", 0xa14: "VMOVNTPS", 0x1abf: "VPMINUD",
0x95f: "PREFETCHNTA", 0x8e0: "VUNPCKLPD", 0x1f50: "VROUNDSD", 0x211c: "VAESKEYGENASSIST",
0x15bd: "PSUBSW", 0x1729: "FNSTENV", 0x1776: "FNSTSW", 0x114c: "CMPNEQPD",
0x151d: "PAVGW", 0x9f9: "MOVNTPD", 0x5cd: "FSETPM", 0x1893: "BLENDVPS", 0x1c6f: "VFMADDSUB213PD",
0xb: "ADD", 0x1f: "ADC", 0x15ac: "PSUBSB", 0x189d: "BLENDVPD", 0xecc: "VPUNPCKHBW",
0x25f: "RDPMC", 0x9f0: "MOVNTPS", 0xbc2: "ANDNPS", 0x1273: "VCMPLTPD", 0x14f0: "PAVGB",
0xdf: "LEA", 0x156f: "VCVTTPD2DQ", 0xe7c: "VPCMPGTB", 0xea2: "VPCMPGTD", 0x46a: "FLD1",
0x1682: "VPMADDWD", 0x14a: "LES", 0x313: "SETZ", 0x1a7a: "VPCMPGTQ", 0xc8c: "VMULSD",
0x1c9f: "VFMADD213PS", 0x1301: "VCMPNLESS", 0x864: "MOVHLPS", 0x1b29: "VPHMINPOSUW",
0x1907: "VPABSD", 0x14ff: "PSRAW", 0x7b6: "PFADD", 0x1b57: "VFMADDSUB132PD",
0xad8: "COMISD", 0x150e: "PSRAD", 0xe09: "VMAXSS", 0x11de: "CMPUNORDSD", 0x4f4: "FSINCOS",
0xad0: "COMISS", 0x1b47: "VFMADDSUB132PS", 0xb86: "RCPPS", 0x1bfd: "VFNMADD132PD",
0x446: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcd2: "VCVTPS2PD", 0xbab: "ANDPD",
0x1e57: "VFNMSUB231PS", 0x643: "FUCOMIP", 0xc74: "VMULPS", 0x1bef: "VFNMADD132PS",
0x38: "DAS", 0x17a: "IRET", 0x3c5: "BSWAP", 0xe19: "PUNPCKLBW", 0x1aea: "PMAXUW",
0x20e8: "VPCMPISTRM", 0x1f34: "ROUNDSS", 0x1d07: "VFNMADD213PS", 0xa60: "VCVTTSD2SI",
0x1df8: "VFMSUB231PD", 0x173a: "FNSTCW", 0x1f47: "ROUNDSD", 0x1160: "CMPNLEPD",
0x1fc0: "PEXTRQ", 0x153f: "PMULHW", 0x593: "FISTP", 0x1a47: "PMOVZXWQ", 0xcdd: "VCVTPD2PS",
0xc50: "VADDSD", 0x1889: "PBLENDVB", 0x6ce: "VMRESUME", 0xab3: "UCOMISD", 0x1a32: "PMOVZXWD",
0xa33: "CVTTPD2PI", 0xaaa: "UCOMISS", 0xe68: "VPACKSSWB", 0xc48: "VADDSS",
0xf99: "PSHUFHW", 0x6e9: "MWAIT"}

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
