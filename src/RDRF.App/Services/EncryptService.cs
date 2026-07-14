using RDRF.Core;
using RDRF.Core.DSAA;

namespace RDRF.App.Services;

public class EncryptService : IEncryptService
{
    public string BackupFile(byte[] password, DSAAAdapter storage, string filePath,
        string primaryStrategy, List<string>? auxiliary = null,
        int fragmentSize = 0, string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
    {
        using var engine = new RDRFEngine(password, storage);
        return engine.BackupFile(
            filePath, primaryStrategy,
            auxiliaryStrategies: auxiliary,
            fragmentSize: fragmentSize,
            customName: customName,
            progress: progress);
    }
}
