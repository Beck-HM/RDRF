using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Storage;

namespace RDRF.App.Services;

public class EncryptService : IDisposable
{
    private readonly byte[] _rcCode;
    private bool _disposed;

    public EncryptService(byte[] password)
    {
        _rcCode = Rfc2898DeriveBytes.Pbkdf2(
            password,
            EncryptionLayer.PasswordSalt,
            600_000,
            HashAlgorithmName.SHA256,
            32);
    }

    public string BackupFile(
        string filePath,
        string outputPath,
        string primaryStrategy,
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
    {
        var storage = new LocalFileAdapter(outputPath);
        using var engine = new RDRFEngine(_rcCode, storage);
        return engine.BackupFile(
            filePath,
            primaryStrategy,
            auxiliaryStrategies: auxiliary,
            fragmentSize: fragmentSize,
            customName: customName,
            progress: progress);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_rcCode is { Length: > 0 })
                CryptographicOperations.ZeroMemory(_rcCode);
            _disposed = true;
        }
    }
}
