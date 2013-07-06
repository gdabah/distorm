
namespace diStorm
{
  public class DecodedResult 
  {
    public DecodedResult(int maxInstructions) 
    {
      MaxInstructions = maxInstructions;
      Instructions = null;
    }
    public DecodedInst[] Instructions { get; internal set; }
    public int MaxInstructions { get; internal set; }
  }
}