using System;

namespace diStorm
{
  public class CodeInfo
  {
    public CodeInfo(long codeOffset, byte[] rawCode, DecodeType dt, int features)
    {
      _code = new byte[rawCode.Length];
      Array.Copy(rawCode, _code, _code.Length);

      _codeOffset = codeOffset;
      _decodeType = dt;
      _features = features;
    }

    internal long _codeOffset;
    internal long _nextOffset;
    internal byte[] _code;
    internal DecodeType _decodeType;
    internal int _features;
  }
}
