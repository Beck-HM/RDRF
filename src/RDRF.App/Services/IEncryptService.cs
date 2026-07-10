using RDRF.Core;
using RDRF.Core.Dssa;

namespace RDRF.App.Services;

public interface IEncryptService
{
    string BackupFile(byte[] password, DssaAdapter storage, string filePath,
        string primaryStrategy, List<string>? auxiliary = null,
        int fragmentSize = 0, string? customName = null,
        IProgress<RdrfProgressReport>? progress = null);
}
