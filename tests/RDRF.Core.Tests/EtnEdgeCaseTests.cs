using System.Security.Cryptography;
using RDRF.Core.Compression;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
/// <summary>
/// Phase 4  - Edge cases and boundary conditions for ETN.
/// </summary>
public class EtnEdgeCaseTests
{
    private readonly ITestOutputHelper _output;

    public EtnEdgeCaseTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void RcFileMissing_RestoreProceedsWithoutValidation()
    {
        // If RC file doesn't exist, restore must continue without cross>validation
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, fingerprint, rcCode) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var storage = new LocalDSAAAdapter(storageDir);
            string rcPath = Path.Combine(storageDir, fingerprint + Constants.RcFileSuffix);

            // Delete the RC file
            File.Delete(rcPath);
            Assert.False(storage.RcExists(fingerprint));

            // Verify restore still succeeds  - full end>to>end
            byte[] encryptedIndex = storage.ReadIndex(fingerprint);
            (byte[] aesKey, byte[] idxCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, rcCode);
            var index = IndexManager.DeserializeIndex(idxCbor);

            string prefix = index.CustomName ?? fingerprint;
            var decrypted = new List<byte[]>();
            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = $"{prefix}_{i}.rdrf";
                byte[] fileBytes = storage.ReadFragment(fname);
                var (_, data, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fileBytes, aesKey);
                // Strip ETN trailer from fragment data
                var cleanData = Fss6Etn.ParseTrailer(data).RawData;
                // Strip padding using OriginalFragmentSizes, then decompress per fragment
                if (index.Compression == Constants.CompressionLz4)
                {
                    int storedSize = (index.OriginalFragmentSizes != null && i < index.OriginalFragmentSizes.Count)
                        ? index.OriginalFragmentSizes[i] : cleanData.Length;
                    byte[] stored = cleanData.AsSpan(0, Math.Min(storedSize, cleanData.Length)).ToArray();
                    try { cleanData = Compression.Compressor.Decompress(stored, Constants.CompressionLz4); }
                    catch { cleanData = stored; }
                }
                decrypted.Add(cleanData);
            }

            string tmpMergePath = Path.Combine(storageDir, $"merge_{Guid.NewGuid():N}.tmp");
            FragmentEngine.Frags.MergeFragments(decrypted, tmpMergePath);
            byte[] restored = File.ReadAllBytes(tmpMergePath);
            try { File.Delete(tmpMergePath); } catch { }
            if (restored.Length > index.FileSize)
                Array.Resize(ref restored, (int)index.FileSize);
            byte[] originalHash = SHA256.HashData(File.ReadAllBytes(EtnTestHelpers.TestFile));
            byte[] restoredHash = SHA256.HashData(restored);
            Assert.Equal(Convert.ToHexString(originalHash), Convert.ToHexString(restoredHash));
            _output.WriteLine("PASS: RC file missing, restore still succeeds");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CrossValidate_WithNullFss6Fields_DoesNotCrash()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Strip FSS6 fields from index (simulate index without ETN metadata)
            var index = IndexManager.DeserializeIndex(indexBytes);
            index.Fss6FragmentBlockMaps = null;
            index.Fss6RcBlockMap = null;
            byte[] strippedIndex = IndexManager.SerializeIndex(index);

            // CrossValidate should handle gracefully (trailer cross>refs still provide
            // some validation even without index's FSS6 fields)
            var result = Fss6Etn.CrossValidate(strippedIndex, fragments, rcBytes);
            Assert.NotNull(result);
            _output.WriteLine("PASS: CrossValidate with null FSS6 fields does not crash");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void FragmentWithoutTrailer_HandledGracefully()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var t0 = Fss6Etn.ParseTrailer(fragments[0]);
            fragments[0] = t0.RawData; // no trailer

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.NotNull(result);
            _output.WriteLine("PASS: Fragment without trailer handled gracefully");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void EmptyTrailer_DoesNotBreakParse()
    {
        var td = EtnTrailer.Parse([]);
        Assert.Empty(td.RawData);
        _output.WriteLine("PASS: Empty trailer parse returns empty");

        var td2 = EtnTrailer.Parse([1, 2, 3]);
        Assert.Equal(3, td2.RawData.Length);
        _output.WriteLine("PASS: Small data without trailer returns data as-is");
    }

    [Fact]
    public void TrailersMatchAcrossAllFragments()
    {
        // All fragments must have identical index block maps in their trailers
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var td0 = Fss6Etn.ParseTrailer(fragments[0]);
            for (int i = 1; i < fragments.Count; i++)
            {
                var tdi = Fss6Etn.ParseTrailer(fragments[i]);
                Assert.True(EtnBlockMap.DiffTrimmed(td0.Index2B, td0.Index2BCount, tdi.Index2B, tdi.Index2BCount, EtnBlockMap.TrailerHashLen).Count == 0,
                    $"Fragment {i} index BM differs from fragment 0");
                Assert.True(EtnBlockMap.DiffTrimmed(td0.Rc2B, td0.Rc2BCount, tdi.Rc2B, tdi.Rc2BCount, EtnBlockMap.TrailerHashLen).Count == 0,
                    $"Fragment {i} RC BM differs from fragment 0");
            }
            _output.WriteLine($"PASS: All {fragments.Count} fragments have consistent trailers");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
}

