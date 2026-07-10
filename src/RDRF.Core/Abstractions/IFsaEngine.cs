using RDRF.Core.FSA;

namespace RDRF.Core.Abstractions;

public interface IFsaEngine
{
    FsaPlan Compute(string primary, List<string>? auxiliary = null);
}
