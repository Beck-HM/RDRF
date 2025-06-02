namespace RDRF.Core.Versioning;

public class DiffChunk
{
    public int OldOffset { get; set; }
    public int OldLength { get; set; }
    public int NewOffset { get; set; }
    public int NewLength { get; set; }
}
