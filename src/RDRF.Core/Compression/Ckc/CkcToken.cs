namespace RDRF.Core.Compression.Ckc;

internal static class CkcConstants
{
    public const int MinMatchLen = 3;
    public const int MaxMatchLen = 258;
}

internal readonly struct CkcToken
{
    public readonly bool IsMatch;
    public readonly byte Literal;
    public readonly int Length;
    public readonly int Distance;
    public readonly int RunLength; // >1 = RLE burst: RunLength literals follow without per-token flag bits

    public CkcToken(byte literal, int runLen = 0)
    { IsMatch = false; Literal = literal; Length = 0; Distance = 0; RunLength = runLen < 0 ? 0 : runLen; }
    public CkcToken(int len, int dist)
    { IsMatch = true; Literal = 0; Length = len; Distance = dist; RunLength = 0; }
}
