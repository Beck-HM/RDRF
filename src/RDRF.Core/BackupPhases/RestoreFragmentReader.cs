using System.Collections.Concurrent;
using System.Security.Cryptography;
using RDRF.Core.Abstractions;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Logging;

namespace RDRF.Core.BackupPhases;

public static class RestoreFragmentReader
{
    public static async Task<Dictionary<int, byte[]>> DownloadAndDecryptFragmentsAsync(
        byte[] aesKey, byte[] rcCode, string filePrefix, int fragmentCount, string fileFingerprint,
        DSAAAdapter storage, IEncryptionLayer encryption, IIndexManager indexManager,
        IProgress<RdrfProgressReport>? progress, CancellationToken ct,
        RdrfIndex? index = null)
    {
        var result = new ConcurrentDictionary<int, byte[]>();
        int decryptErrors = 0;

        var sourceKeys = new Dictionary<string, byte[]>();
        if (index?.Fragments != null)
        {
            for (int i = 0; i < fragmentCount && i < index.Fragments.Count; i++)
            {
                string? sv = index.Fragments[i].SourceVersion;
                if (sv != null && !sourceKeys.ContainsKey(sv))
                {
                    byte[] srcIdx = await storage.ReadIndexAsync(sv, ct).ConfigureAwait(false);
                    byte[] salt = srcIdx.AsSpan(0, RDRF.Core.Constants.SaltPrefixLength).ToArray();
                    sourceKeys[sv] = encryption.DeriveKey(rcCode, salt);
                }
            }
        }

        await Parallel.ForEachAsync(
            Enumerable.Range(0, fragmentCount),
            new ParallelOptions { MaxDegreeOfParallelism = RDRF.Core.Constants.DefaultParallelism },
            async (i, ct2) =>
            {
                ct2.ThrowIfCancellationRequested();
                try
                {
                    string sourceFp = fileFingerprint;
                    string sourcePrefix = filePrefix;
                    byte[] key = aesKey;

                    if (index?.Fragments?.Count > i && index.Fragments[i].SourceVersion != null)
                    {
                        sourceFp = index.Fragments[i].SourceVersion;
                        sourcePrefix = sourceFp;
                        if (sourceKeys.TryGetValue(sourceFp, out var cachedKey))
                            key = cachedKey;
                    }

                    int sourceIdx = i;
                    if (index?.Fragments?.Count > i && index.Fragments[i].SourceIndex.HasValue)
                        sourceIdx = index.Fragments[i].SourceIndex.Value;

                    string fname = Frags.FragmentFilename(sourcePrefix, sourceIdx);
                    byte[] encrypted = await storage.ReadFragmentAsync(fname, ct2)
                        .ConfigureAwait(false);
                    byte[] raw = encryption.DecryptAndStripFragment(encrypted, key);
                    result[i] = raw;
                }
                catch (CryptographicException)
                {
                    Interlocked.Increment(ref decryptErrors);
                }
                catch
                {
                    Interlocked.Increment(ref decryptErrors);
                }
            });

        if (decryptErrors > 0 && result.Count == 0)
            throw new CryptographicException("All fragments failed to decrypt.");

        return new Dictionary<int, byte[]>(result);
    }
}
