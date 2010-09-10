# :[diStorm3}: Python binding
# Based on diStorm64 Python binding by Mario Vilas
# Initial support for decompose API added by Roee Shenberg
# Changed license to GPLv3.

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
try:
    # Give a try for Windows.
    _distorm_file = join(_distorm_path, 'distorm3.dll')
    _distorm = cdll.LoadLibrary(_distorm_file)
except OSError:
    try:
        # Linux
        _distorm_file = join(_distorm_path, 'libdistorm3.so')
        _distorm = cdll.LoadLibrary(_distorm_file)
    except OSError:
        try:
            # Mac
            _distorm_file = join(_distorm_path, 'libdistorm3.dylib')
            _distorm = cdll.LoadLibrary(_distorm_file)
        except OSError:
            raise ImportError("Error loading distorm")

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

MAX_TEXT_SIZE       = 32 # See distorm.h for this value.
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
        ('addr',  _OffsetType),
        ('size', c_ubyte),
        ('flags',  c_uint16), # -1 if invalid. See C headers for more info
        ('segment', c_ubyte),
        ('base', c_ubyte),    # base register for indirections
        ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
        ('dispSize', c_ubyte),
        ('opcode', c_uint16),  # look up in opcode table
        ('ops', _Operand*4),
        ('disp', c_uint64),    # displacement. size is according to dispSize
        ('imm', _Value),
        ('unusedPrefixesMask', c_uint16),
        ('meta', c_ubyte), # meta flags - instruction set class, etc. See C headers again...
    ]


#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType)

Mnemonics = ["ADD", "PUSH", "POP", "OR", "ADC", "SBB", "AND", "DAA", "SUB", "DAS", "XOR", "AAA", "CMP", "AAS",
"INC", "DEC", "PUSHA", "POPA", "BOUND", "ARPL", "IMUL", "INS", "OUTS", "JO", "JNO", "JB", "JAE",
"JZ", "JNZ", "JBE", "JA", "JS", "JNS", "JP", "JNP", "JL", "JGE", "JLE", "JG", "TEST", "XCHG", "MOV",
"LEA", "CBW", "CWDE", "CDQE", "CWD", "CDQ", "CQO", "CALL FAR", "PUSHF", "POPF", "SAHF", "LAHF",
"MOVS", "CMPS", "STOS", "LODS", "SCAS", "RET", "LES", "LDS", "ENTER", "LEAVE", "RETF", "INT 3",
"INT", "INTO", "IRET", "AAM", "AAD", "SALC", "XLAT", "LOOPNZ", "LOOPZ", "LOOP", "JCXZ", "JECXZ",
"JRCXZ", "IN", "OUT", "CALL", "JMP", "JMP FAR", "INT1", "HLT", "CMC", "CLC", "STC", "CLI", "STI",
"CLD", "STD", "LAR", "LSL", "SYSCALL", "CLTS", "SYSRET", "INVD", "WBINVD", "UD2", "FEMMS", "NOP",
"WRMSR", "RDTSC", "RDMSR", "RDPMC", "SYSENTER", "SYSEXIT", "GETSEC", "CMOVO", "CMOVNO",
"CMOVB", "CMOVAE", "CMOVZ", "CMOVNZ", "CMOVBE", "CMOVA", "CMOVS", "CMOVNS", "CMOVP", "CMOVNP",
"CMOVL", "CMOVGE", "CMOVLE", "CMOVG", "SETO", "SETNO", "SETB", "SETAE", "SETZ", "SETNZ", "SETBE",
"SETA", "SETS", "SETNS", "SETP", "SETNP", "SETL", "SETGE", "SETLE", "SETG", "CPUID", "BT", "SHLD",
"RSM", "BTS", "SHRD", "CMPXCHG", "LSS", "BTR", "LFS", "LGS", "MOVZX", "BTC", "BSF", "MOVSX", "XADD",
"MOVNTI", "BSWAP", "SLDT", "STR", "LLDT", "LTR", "VERR", "VERW", "SGDT", "SIDT", "LGDT", "LIDT",
"SMSW", "LMSW", "INVLPG", "VMCALL", "VMLAUNCH", "VMRESUME", "VMXOFF", "MONITOR", "MWAIT",
"XGETBV", "XSETBV", "VMRUN", "VMMCALL", "VMLOAD", "VMSAVE", "STGI", "CLGI", "SKINIT", "INVLPGA",
"SWAPGS", "RDTSCP", "PREFETCH", "PREFETCHW", "PI2FW", "PI2FD", "PF2IW", "PF2ID", "PFNACC",
"PFPNACC", "PFCMPGE", "PFMIN", "PFRCP", "PFRSQRT", "PFSUB", "PFADD", "PFCMPGT", "PFMAX",
"PFRCPIT1", "PFRSQIT1", "PFSUBR", "PFACC", "PFCMPEQ", "PFMUL", "PFRCPIT2", "PMULHRW",
"PSWAPD", "PAVGUSB", "MOVUPS", "MOVUPD", "MOVSS", "MOVSD", "VMOVSS", "VMOVSD", "VMOVUPS",
"VMOVUPD", "MOVHLPS", "MOVLPS", "MOVLPD", "MOVSLDUP", "MOVDDUP", "VMOVHLPS", "VMOVLPS",
"VMOVLPD", "VMOVSLDUP", "VMOVDDUP", "UNPCKLPS", "UNPCKLPD", "VUNPCKLPS", "VUNPCKLPD",
"UNPCKHPS", "UNPCKHPD", "VUNPCKHPS", "VUNPCKHPD", "MOVLHPS", "MOVHPS", "MOVHPD", "MOVSHDUP",
"VMOVLHPS", "VMOVHPS", "VMOVHPD", "VMOVSHDUP", "PREFETCHNTA", "PREFETCHT0", "PREFETCHT1",
"PREFETCHT2", "MOVAPS", "MOVAPD", "VMOVAPS", "VMOVAPD", "CVTPI2PS", "CVTPI2PD", "CVTSI2SS",
"CVTSI2SD", "VCVTSI2SS", "VCVTSI2SD", "MOVNTPS", "MOVNTPD", "MOVNTSS", "MOVNTSD", "VMOVNTPS",
"VMOVNTPD", "CVTTPS2PI", "CVTTPD2PI", "CVTTSS2SI", "CVTTSD2SI", "VCVTTSS2SI", "VCVTTSD2SI",
"CVTPS2PI", "CVTPD2PI", "CVTSS2SI", "CVTSD2SI", "VCVTSS2SI", "VCVTSD2SI", "UCOMISS",
"UCOMISD", "VUCOMISS", "VUCOMISD", "COMISS", "COMISD", "VCOMISS", "VCOMISD", "PSHUFB",
"VPSHUFB", "PHADDW", "VPHADDW", "PHADDD", "VPHADDD", "PHADDSW", "VPHADDSW", "PMADDUBSW",
"VPMADDUBSW", "PHSUBW", "VPHSUBW", "PHSUBD", "VPHSUBD", "PHSUBSW", "VPHSUBSW", "PSIGNB",
"VPSIGNB", "PSIGNW", "VPSIGNW", "PSIGND", "VPSIGND", "PMULHRSW", "VPMULHRSW", "VPERMILPS",
"VPERMILPD", "VPTESTPS", "VPTESTPD", "PBLENDVB", "BLENDVPS", "BLENDVPD", "PTEST", "VPTEST",
"VBROADCASTSS", "VBROADCASTSD", "VBROADCASTF128", "PABSB", "VPABSB", "PABSW", "VPABSW",
"PABSD", "VPABSD", "PMOVSXBW", "VPMOVSXBW", "PMOVSXBD", "VPMOVSXBD", "PMOVSXBQ", "VPMOVSXBQ",
"PMOVSXWD", "VPMOVSXWD", "PMOVSXWQ", "VPMOVSXWQ", "PMOVSXDQ", "VPMOVSXDQ", "PMULDQ",
"VPMULDQ", "PCMPEQQ", "VPCMPEQQ", "MOVNTDQA", "VMOVNTDQA", "PACKUSDW", "VPACKUSDW",
"VMASKMOVPS", "VMASKMOVPD", "PMOVZXBW", "VPMOVZXBW", "PMOVZXBD", "VPMOVZXBD", "PMOVZXBQ",
"VPMOVZXBQ", "PMOVZXWD", "VPMOVZXWD", "PMOVZXWQ", "VPMOVZXWQ", "PMOVZXDQ", "VPMOVZXDQ",
"PCMPGTQ", "VPCMPGTQ", "PMINSB", "VPMINSB", "PMINSD", "VPMINSD", "PMINUW", "VPMINUW",
"PMINUD", "VPMINUD", "PMAXSB", "VPMAXSB", "PMAXSD", "VPMAXSD", "PMAXUW", "VPMAXUW", "PMAXUD",
"VPMAXUD", "PMULLD", "VPMULLD", "PHMINPOSUW", "VPHMINPOSUW", "INVEPT", "INVVPID", "VFMADDSUB132PS",
"VFMADDSUB132PD", "VFMSUBADD132PS", "VFMSUBADD132PD", "VFMADD132PS", "VFMADD132PD",
"VFMADD132SS", "VFMADD132SD", "VFMSUB132PS", "VFMSUB132PD", "VFMSUB132SS", "VFMSUB132SD",
"VFNMADD132PS", "VFNMADD132PD", "VFNMADD132SS", "VFNMADD132SD", "VFNMSUB132PS",
"VFNMSUB132PD", "VFNMSUB132SS", "VFNMSUB132SD", "VFMADDSUB213PS", "VFMADDSUB213PD",
"VFMSUBADD213PS", "VFMSUBADD213PD", "VFMADD213PS", "VFMADD213PD", "VFMADD213SS",
"VFMADD213SD", "VFMSUB213PS", "VFMSUB213PD", "VFMSUB213SS", "VFMSUB213SD", "VFNMADD213PS",
"VFNMADD213PD", "VFNMADD213SS", "VFNMADD213SD", "VFNMSUB213PS", "VFNMSUB213PD",
"VFNMSUB213SS", "VFNMSUB213SD", "VFMADDSUB231PS", "VFMADDSUB231PD", "VFMSUBADD231PS",
"VFMSUBADD231PD", "VFMADD231PS", "VFMADD231PD", "VFMADD231SS", "VFMADD231SD", "VFMSUB231PS",
"VFMSUB231PD", "VFMSUB231SS", "VFMSUB231SD", "VFNMADD231PS", "VFNMADD231PD", "VFNMADD231SS",
"VFNMADD231SD", "VFNMSUB231PS", "VFNMSUB231PD", "VFNMSUB231SS", "VFNMSUB231SD",
"AESIMC", "VAESIMC", "AESENC", "VAESENC", "AESENCLAST", "VAESENCLAST", "AESDEC", "VAESDEC",
"AESDECLAST", "VAESDECLAST", "MOVBE", "CRC32", "VPERM2F128", "ROUNDPS", "VROUNDPS",
"ROUNDPD", "VROUNDPD", "ROUNDSS", "VROUNDSS", "ROUNDSD", "VROUNDSD", "BLENDPS", "VBLENDPS",
"BLENDPD", "VBLENDPD", "PBLENDW", "VPBLENDVW", "PALIGNR", "VPALIGNR", "PEXTRB", "VPEXTRB",
"PEXTRW", "VPEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRD", "EXTRACTPS", "VEXTRACTPS", "VINSERTF128",
"VEXTRACTF128", "PINSRB", "VPINSRB", "INSERTPS", "VINSERTPS", "PINSRD", "PINSRQ", "VPINSRD",
"VPINSRQ", "DPPS", "VDPPS", "DPPD", "VDPPD", "MPSADBW", "VMPSADBW", "PCLMULQDQ", "VPCLMULQDQ",
"VBLENDVPS", "VBLENDVPD", "VPBLENDVB", "PCMPESTRM", "VPCMPESTRM", "PCMPESTRI", "VCMPESTRI",
"PCMPISTRM", "VPCMPISTRM", "PCMPISTRI", "VPCMPISTRI", "AESKEYGENASSIST", "VAESKEYGENASSIST",
"MOVMSKPS", "MOVMSKPD", "VMOVMSKPS", "VMOVMSKPD", "SQRTPS", "SQRTPD", "SQRTSS", "SQRTSD",
"VSQRTSS", "VSQRTSD", "VSQRTPS", "VSQRTPD", "RSQRTPS", "RSQRTSS", "VRSQRTSS", "VRSQRTPS",
"RCPPS", "RCPSS", "VRCPSS", "VRCPPS", "ANDPS", "ANDPD", "VANDPS", "VANDPD", "ANDNPS", "ANDNPD",
"VANDNPS", "VANDNPD", "ORPS", "ORPD", "VORPS", "VORPD", "XORPS", "XORPD", "VXORPS", "VXORPD",
"ADDPS", "ADDPD", "ADDSS", "ADDSD", "VADDPS", "VADDPD", "VADDSS", "VADDSD", "MULPS", "MULPD",
"MULSS", "MULSD", "VMULPS", "VMULPD", "VMULSS", "VMULSD", "CVTPS2PD", "CVTPD2PS", "CVTSS2SD",
"CVTSD2SS", "VCVTSS2SD", "VCVTSD2SS", "VCVTPS2PD", "VCVTPD2PS", "CVTDQ2PS", "CVTPS2DQ",
"CVTTPS2DQ", "VCVTDQ2PS", "VCVTPS2DQ", "VCVTTPS2DQ", "SUBPS", "SUBPD", "SUBSS", "SUBSD",
"VSUBPS", "VSUBPD", "VSUBSS", "VSUBSD", "MINPS", "MINPD", "MINSS", "MINSD", "VMINPS", "VMINPD",
"VMINSS", "VMINSD", "DIVPS", "DIVPD", "DIVSS", "DIVSD", "VDIVPS", "VDIVPD", "VDIVSS", "VDIVSD",
"MAXPS", "MAXPD", "MAXSS", "MAXSD", "VMAXPS", "VMAXPD", "VMAXSS", "VMAXSD", "PUNPCKLBW",
"VPUNPCKLBW", "PUNPCKLWD", "VPUNPCKLWD", "PUNPCKLDQ", "VPUNPCKLDQ", "PACKSSWB", "VPACKSSWB",
"PCMPGTB", "VPCMPGTB", "PCMPGTW", "VPCMPGTW", "PCMPGTD", "VPCMPGTD", "PACKUSWB", "VPACKUSWB",
"PUNPCKHBW", "VPUNPCKHBW", "PUNPCKHWD", "VPUNPCKHWD", "PUNPCKHDQ", "VPUNPCKHDQ", "PACKSSDW",
"VPACKSSDW", "PUNPCKLQDQ", "VPUNPCKLQDQ", "PUNPCKHQDQ", "VPUNPCKHQDQ", "MOVD", "MOVQ",
"VMOVD", "VMOVQ", "MOVDQA", "MOVDQU", "VMOVDQA", "VMOVDQU", "PSHUFW", "PSHUFD", "PSHUFHW",
"PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW", "PSRLW", "VPSRLW", "PSRAW", "VPSRAW", "PSLLW",
"VPSLLW", "PSRLD", "VPSRLD", "PSRAD", "VPSRAD", "PSLLD", "VPSLLD", "PSRLQ", "VPSRLQ", "PSRLDQ",
"VPSRLDQ", "PSLLQ", "VPSLLQ", "PSLLDQ", "VPSLLDQ", "PCMPEQB", "VPCMPEQB", "PCMPEQW", "VPCMPEQW",
"PCMPEQD", "VPCMPEQD", "EMMS", "VZEROUPPER", "VZEROALL", "VMREAD", "EXTRQ", "INSERTQ",
"VMWRITE", "HADDPD", "HADDPS", "VHADDPD", "VHADDPS", "HSUBPD", "HSUBPS", "VHSUBPD", "VHSUBPS",
"FXSAVE", "FXRSTOR", "XAVE", "LFENCE", "XRSTOR", "MFENCE", "SFENCE", "CLFLUSH", "LDMXCSR",
"VLDMXCSR", "STMXCSR", "VSTMXCSR", "POPCNT", "BSR", "LZCNT", "CMPEQPS", "CMPLTPS", "CMPLEPS",
"CMPUNORDPS", "CMPNEQPS", "CMPNLTPS", "CMPNLEPS", "CMPORDPS", "CMPEQPD", "CMPLTPD",
"CMPLEPD", "CMPUNORDPD", "CMPNEQPD", "CMPNLTPD", "CMPNLEPD", "CMPORDPD", "CMPEQSS",
"CMPLTSS", "CMPLESS", "CMPUNORDSS", "CMPNEQSS", "CMPNLTSS", "CMPNLESS", "CMPORDSS",
"CMPEQSD", "CMPLTSD", "CMPLESD", "CMPUNORDSD", "CMPNEQSD", "CMPNLTSD", "CMPNLESD", "CMPORDSD",
"VCMPEQPS", "VCMPLTPS", "VCMPLEPS", "VCMPUNORDPS", "VCMPNEQPS", "VCMPNLTPS", "VCMPNLEPS",
"VCMPORDPS", "VCMPEQPD", "VCMPLTPD", "VCMPLEPD", "VCMPUNORDPD", "VCMPNEQPD", "VCMPNLTPD",
"VCMPNLEPD", "VCMPORDPD", "VCMPEQSS", "VCMPLTSS", "VCMPLESS", "VCMPUNORDSS", "VCMPNEQSS",
"VCMPNLTSS", "VCMPNLESS", "VCMPORDSS", "VCMPEQSD", "VCMPLTSD", "VCMPLESD", "VCMPUNORDSD",
"VCMPNEQSD", "VCMPNLTSD", "VCMPNLESD", "VCMPORDSD", "PINSRW", "VPINSRW", "SHUFPS", "SHUFPD",
"VSHUFPS", "VSHUFPD", "CMPXCHG8B", "CMPXCHG16B", "VMPTRST", "VMPTRLD", "VMCLEAR", "VMXON",
"ADDSUBPD", "ADDSUBPS", "VADDSUBPD", "VADDSUBPS", "PADDQ", "VPADDQ", "PMULLW", "VPMULLW",
"MOVQ2DQ", "MOVDQ2Q", "PMOVMSKB", "VPMOVMSKB", "PSUBUSB", "VPSUBUSB", "PSUBUSW", "VPSUBUSW",
"PMINUB", "VPMINUB", "PAND", "VPAND", "PADDUSB", "VPADDUSW", "PADDUSW", "PMAXUB", "VPMAXUB",
"PANDN", "VPANDN", "PAVGB", "VPAVGB", "PAVGW", "VPAVGW", "PMULHUW", "VPMULHUW", "PMULHW",
"VPMULHW", "CVTTPD2DQ", "CVTDQ2PD", "CVTPD2DQ", "VCVTTPD2DQ", "VCVTDQ2PD", "VCVTPD2DQ",
"MOVNTQ", "MOVNTDQ", "VMOVNTDQ", "PSUBSB", "VPSUBSB", "PSUBSW", "VPSUBSW", "PMINSW", "VPMINSW",
"POR", "VPOR", "PADDSB", "VPADDSB", "PADDSW", "VPADDSW", "PMAXSW", "VPMAXSW", "PXOR", "VPXOR",
"LDDQU", "VLDDQU", "PMULUDQ", "VPMULUDQ", "PMADDWD", "VPMADDWD", "PSADBW", "VPSADBW",
"MASKMOVQ", "MASKMOVDQU", "VMASKMOVDQU", "PSUBB", "VPSUBB", "PSUBW", "VPSUBW", "PSUBD",
"VPSUBD", "PSUBQ", "VPSUBQ", "PADDB", "VPADDB", "PADDW", "VPADDW", "PADDD", "VPADDD", "ROL",
"ROR", "RCL", "RCR", "SHL", "SHR", "SAL", "SAR", "FADD", "FMUL", "FCOM", "FCOMP", "FSUB", "FSUBR",
"FDIV", "FDIVR", "FLD", "FST", "FSTP", "FLDENV", "FLDCW", "FXCH", "FNOP", "FCHS", "FABS", "FTST",
"FXAM", "FLD1", "FLDL2T", "FLDL2E", "FLDPI", "FLDLG2", "FLDLN2", "FLDZ", "F2XM1", "FYL2X",
"FPTAN", "FPATAN", "FXTRACT", "FPREM1", "FDECSTP", "FINCSTP", "FPREM", "FYL2XP1", "FSQRT",
"FSINCOS", "FRNDINT", "FSCALE", "FSIN", "FCOS", "FNSTENV", "FSTENV", "FNSTCW", "FSTCW",
"FIADD", "FIMUL", "FICOM", "FICOMP", "FISUB", "FISUBR", "FIDIV", "FIDIVR", "FCMOVB", "FCMOVE",
"FCMOVBE", "FCMOVU", "FUCOMPP", "FILD", "FISTTP", "FIST", "FISTP", "FCMOVNB", "FCMOVNE",
"FCMOVNBE", "FCMOVNU", "FENI", "FEDISI", "FSETPM", "FUCOMI", "FCOMI", "FNCLEX", "FCLEX",
"FNINIT", "FINIT", "FRSTOR", "FFREE", "FUCOM", "FUCOMP", "FNSAVE", "FSAVE", "FNSTSW", "FSTSW",
"FADDP", "FMULP", "FCOMPP", "FSUBRP", "FSUBP", "FDIVRP", "FDIVP", "FBLD", "FBSTP", "FUCOMIP",
"FCOMIP", "NOT", "NEG", "MUL", "DIV", "IDIV", "WAIT", "MOVSXD", "PAUSE"]

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
    code            = create_string_buffer(code)
    p_code          = addressof(code)
    result          = (_DecodedInst * MAX_INSTRUCTIONS)()
    p_result        = byref(result)

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
            yield pydi

        di         = result[used - 1]
        delta      = di.offset - codeOffset + result[used -1].size
        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = p_code + delta
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
    return Mnemonics[opcode - 1]

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
    def __init__(self, di, instructionBytes):
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
        self.dt = _getOpSize(flags)
        self.valid = False

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
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.im1, operand.size)
        elif operand.type == O_IMM2: # second operand for ENTER
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.im2, operand.size)
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
    scode           = create_string_buffer(code)
    p_code          = addressof(scode)
    result          = (_DInst * MAX_INSTRUCTIONS)()
    instruction_off = 0

    while codeLen > 0:

        usedInstructionsCount = c_uint(0)
        codeInfo = _CodeInfo(_OffsetType(codeOffset), _OffsetType(0), p_code, codeLen, dt, 0)
        status = internal_decompose(byref(codeInfo), byref(result), MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        delta = 0
        for index in xrange(used):
            di = result[index]
            yield Instruction(di, code[instruction_off : instruction_off + di.size])
            delta += di.size
            instruction_off += di.size

        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = p_code + delta
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
