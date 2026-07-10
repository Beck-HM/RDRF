using RDRF.Core.Index;

namespace RDRF.Core.Abstractions;

public interface IRecoveryExecutor
{
    RecoveryResult ExecuteRecovery(RdrfIndex index, Dictionary<int, byte[]> availableFragments, IMetadataManager? metadata = null);
    Task<RecoveryResult> ExecuteRecoveryAsync(RdrfIndex index, Dictionary<int, byte[]> availableFragments, IMetadataManager? metadata = null);
}
