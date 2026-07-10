using RDRF.Core;
using RDRF.Core.Dssa;

namespace RDRF.App.Services;

public interface IDecryptService : IDisposable
{
    BackupLoadResult? LoadResult { get; }
    bool IsFragmentMode { get; }
    string? FilePrefix { get; }
    string? StoragePath { get; }

    BackupLoadResult LoadFromIndex(string storagePath, string indexPath);
    BackupLoadResult LoadFromFragment(string storagePath, string filePrefix);
    List<FragmentStatusInfo> ScanFragments();
    bool Restore(string outputPath, IProgress<RdrfProgressReport>? progress = null);
}
