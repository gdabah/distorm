namespace diStorm
{
  public class DecomposedResult
  {
    public DecomposedResult(int maxInstructions)
    {
      MaxInstructions = maxInstructions;
      Instructions = null;
    }

    public DecomposedInst[] Instructions { get; internal set; }
    public int MaxInstructions { get; private set; }
  }
}