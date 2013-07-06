
namespace diStorm
{

  public enum OperandType : byte
  {
    None,
    Reg,
    Imm,
    Imm1,
    Imm2,
    Disp,
    Smem,
    Mem,
    Pc,
    Ptr
  }

  public class Operand
  {
    public OperandType Type { get; internal set; }
    public int Index { get; internal set; }
    public int Size { get; internal set; }
  }
}