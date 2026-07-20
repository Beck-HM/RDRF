namespace RDRF.Core.Compression.Ckc;

internal static class CkcDistSlot
{
    public static int SlotCount => 30;

    public static (int slot, int extraBits) Map(int distance)
    {
        if (distance <= 4) return (distance - 1, 0);
        if (distance <= 6) return (4, 1);
        if (distance <= 10) return (5, 2);
        if (distance <= 18) return (6, 3);
        if (distance <= 34) return (7, 4);
        if (distance <= 66) return (8, 5);
        if (distance <= 130) return (9, 6);
        if (distance <= 258) return (10, 7);
        if (distance <= 514) return (11, 8);
        if (distance <= 1026) return (12, 9);
        if (distance <= 2050) return (13, 10);
        if (distance <= 4098) return (14, 11);
        if (distance <= 8194) return (15, 12);
        if (distance <= 16386) return (16, 13);
        if (distance <= 32770) return (17, 14);
        if (distance <= 65538) return (18, 15);
        if (distance <= 131074) return (19, 16);
        if (distance <= 262146) return (20, 17);
        if (distance <= 524290) return (21, 18);
        if (distance <= 1048578) return (22, 19);
        if (distance <= 2097154) return (23, 20);
        if (distance <= 4194306) return (24, 21);
        if (distance <= 8388610) return (25, 22);
        if (distance <= 16777218) return (26, 23);
        if (distance <= 33554434) return (27, 24);
        if (distance <= 67108866) return (28, 25);
        return (29, 25);
    }
}
