using System.Diagnostics;
using RDRF.Core.Compression;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Core.DSAA;

namespace RDRF.Core.Versioning;

/// <summary>
/// Restore a specific version from a real-incremental backup.
/// Finds the target version's fingerprint and delegates to the
/// standard RDRFEngine for the actual restore.
/// </summary>
public static class RealVersionedRestore
{
    public static bool RestoreVersion(
        DSAAAdapter storage, string latestFingerprint, int targetVersion,
        string outputPath, byte[] password,
        IProgress<RdrfProgressReport>? progress = null)
    {
        return Task.Run(() => RestoreVersionAsync(storage, latestFingerprint, targetVersion,
            outputPath, password, progress, CancellationToken.None))
            .GetAwaiter().GetResult();
    }

    public static async Task<bool> RestoreVersionAsync(
        DSAAAdapter storage, string latestFingerprint, int targetVersion,
        string outputPath, byte[] password,
        IProgress<RdrfProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        // Find target version's fingerprint
        byte[] encIdx = storage.ReadIndex(latestFingerprint);
        (byte[] _, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var idx = IndexManager.DeserializeIndex(cbor);

        string targetFp;
        if ((idx.VersionNumber ?? 0) == targetVersion)
            targetFp = latestFingerprint;
        else if (idx.Versions != null)
        {
            var found = idx.Versions.FirstOrDefault(vr => vr.Version == targetVersion);
            if (found != null) targetFp = found.FileFingerprint;
            else throw new InvalidOperationException($"Version {targetVersion} not found");
        }
        else throw new InvalidOperationException($"Version {targetVersion} not found");

        // Use standard engine. The engine's StreamingRestore path handles
        // SourceVersion correctly. For FSS strategies with issues in that
        // path, we fall back to the full DownloadAndDecrypt path.
        using var engine = new RDRFEngine(password, storage);
        return await engine.RestoreFileAsync(targetFp, outputPath,
            filePrefix: targetFp, progress: progress, cancellationToken: ct).ConfigureAwait(false);
    }
}
