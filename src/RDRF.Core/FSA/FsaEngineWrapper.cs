using RDRF.Core.Abstractions;

namespace RDRF.Core.FSA;

public class FsaEngineWrapper : IFsaEngine
{
    private readonly FsaEngine _inner = new();

    public FsaPlan Compute(string primary, List<string>? auxiliary = null)
        => _inner.Compute(primary, auxiliary);
}
