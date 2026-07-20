using RDRF.Core.Index;

namespace RDRF.Core.Abstractions;

/// <summary>
/// Executes FSS-based fragment recovery using available fragments and the backup index.
/// </summary>
public interface IRecoveryExecutor
{
    /// <summary>Attempts to recover missing fragments synchronously.</summary>
    RecoveryResult ExecuteRecovery(RdrfIndex index, Dictionary<int, byte[]> availableFragments, IMetadataManager? metadata = null);

    /// <summary>Attempts to recover missing fragments asynchronously.</summary>
    Task<RecoveryResult> ExecuteRecoveryAsync(RdrfIndex index, Dictionary<int, byte[]> availableFragments, IMetadataManager? metadata = null);
}
