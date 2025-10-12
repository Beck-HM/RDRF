using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Dssa;

namespace RDRF.App.Services;

public class EncryptService : IDisposable
{
    private readonly byte[] _rcCode;
    private readonly DssaAdapter _storage;
    private bool _disposed;

    public EncryptService(byte[] password, DssaAdapter storage)
    {
        _rcCode = (byte[])password.Clone();
        _storage = storage;
    }

    public string BackupFile(
        string filePath,
        string primaryStrategy,
        List<string>? auxiliary = null,
        int fragmentSize = 0,
        string? customName = null,
        IProgress<RdrfProgressReport>? progress = null)
    {
        using var engine = new RDRFEngine(_rcCode, _storage);
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
