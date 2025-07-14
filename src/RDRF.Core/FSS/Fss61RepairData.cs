namespace RDRF.Core.FSS;

public class Fss61RepairData
{
    public int Seed { get; set; }
    public int BlockCount { get; set; }
    public int BlockSize { get; set; } = 256;
    public byte[] Data { get; set; } = [];
}
