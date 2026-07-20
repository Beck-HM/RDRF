namespace RDRF.Core;

public static class Adler32
{
    public const uint Init = 1;

    public static uint Update(uint adler, ReadOnlySpan<byte> data)
    {
        const uint Mod = 65521;
        uint a = adler & 0xFFFF;
        uint b = (adler >> 16) & 0xFFFF;
        foreach (byte t in data)
        {
            a = (a + t) % Mod;
            b = (b + a) % Mod;
        }
        return (b << 16) | a;
    }
}
