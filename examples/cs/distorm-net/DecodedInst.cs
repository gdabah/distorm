using System;

namespace diStorm
{
  public class DecodedInst
  {
    internal DecodedInst() { }
    
    public string Mnemonic { get; internal set; }
    public string Operands { get; internal set; }
    public string Hex { get; internal set; }
    public uint Size { get; internal set; }
    public IntPtr Offset { get; internal set; }
  }
}