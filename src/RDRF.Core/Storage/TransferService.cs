using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;

namespace RDRF.Core.DSAA;

public static class TransferService
{
    /// <summary>
    /// Stream fragments + index + RC from source storage directory to destination storage directory.
    /// Uses local DSAAAdapter for both source and destination.
    /// </summary>
    public static async Task<int> Run(
        string indexPath, byte[] password,
        string dstDir, bool dryRun = false, bool keepSource = false,
        int concurrency = 1, IProgress<RdrfProgressReport>? progress = null)
    {
        if (password.Length == 0) { Console.Error.WriteLine("Error: password cannot be empty"); return 1; }
        if (!Directory.Exists(dstDir)) { Directory.CreateDirectory(dstDir); }

        byte[] encryptedIndex = await File.ReadAllBytesAsync(indexPath);
        (byte[] _, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string prefix = index.CustomName ?? index.FileFingerprint;
        string srcDir = Path.GetDirectoryName(Path.GetFullPath(indexPath))!;

        var srcStorage = new LocalDSAAAdapter(srcDir);
        var dstStorage = new LocalDSAAAdapter(dstDir);

        int fragmentCount = index.FragmentCount;
        if (dryRun)
        {
            Console.WriteLine($"Would transfer {fragmentCount} fragments from '{srcDir}' to '{dstDir}'.");
            Console.WriteLine($"  Fingerprint: {index.FileFingerprint}");
            return 0;
        }

        Console.WriteLine($"Transferring {fragmentCount} fragments from '{srcDir}' to '{dstDir}'...");

        int errors = 0;
        using var semaphore = new SemaphoreSlim(concurrency);
        var tasks = new List<Task>();

        for (int i = 0; i < fragmentCount; i++)
        {
            int fi = i;
            await semaphore.WaitAsync();
            var t = Task.Run(async () =>
            {
                try
                {
                    string fragName = Frags.FragmentFilename(prefix, fi);
                    if (!srcStorage.FragmentExists(fragName))
                    {
                        Console.Error.WriteLine($"Warning: fragment {fi} not found at source, skipping.");
                        return;
                    }

                    byte[] fragData = srcStorage.ReadFragment(fragName);
                    await dstStorage.WriteFragmentViaStreamAsync(fragName, async (stream, ct) =>
                    {
                        await stream.WriteAsync(fragData.AsMemory(0, fragData.Length), ct).ConfigureAwait(false);
                    });

                    progress?.Report(new RdrfProgressReport { Stage = "Transferring", CurrentItem = fi + 1, TotalItems = fragmentCount });
                    if (!keepSource) { try { srcStorage.DeleteFragment(fragName); } catch { } }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error transferring fragment {fi}: {ex.Message}");
                    Interlocked.Increment(ref errors);
                }
                finally { semaphore.Release(); }
            });
            tasks.Add(t);
        }

        await Task.WhenAll(tasks);
        if (errors > 0) { Console.Error.WriteLine($"Transfer completed with {errors} errors."); return 1; }

        // Transfer index
        try
        {
            dstStorage.WriteIndex(prefix, encryptedIndex);
        }
        catch (Exception ex) { Console.Error.WriteLine($"Error transferring index: {ex.Message}"); return 1; }

        // Transfer RC
        if (srcStorage.RcExists(prefix))
        {
            try
            {
                byte[] rcData = srcStorage.ReadRc(prefix);
                dstStorage.WriteRc(prefix, rcData);
            }
            catch (Exception ex) { Console.Error.WriteLine($"Error transferring RC: {ex.Message}"); return 1; }
        }

        // Delete source index if not keeping
        if (!keepSource) { try { File.Delete(indexPath); } catch { } }

        Console.WriteLine($"Transfer complete. {fragmentCount} fragments, index, RC moved to '{dstDir}'.");
        return 0;
    }
}
