using System.Security.Cryptography;
using RDRF.Core.Encryption;
using RDRF.Core.ETN;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
/// <summary>
/// Phase 4 鈥?Edge cases and boundary conditions for ETN.
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

            var storage = new LocalFileAdapter(storageDir);
            string rcPath = Path.Combine(storageDir, fingerprint + Constants.RcFileSuffix);

            // Delete the RC file
            File.Delete(rcPath);
            Assert.False(storage.RcExists(fingerprint));

            // Verify restore still succeeds 鈥?full end>to>end
            byte[] aesKey = EncryptionLayer.DeriveKey(rcCode);
            byte[] encryptedIndex = storage.ReadIndex(fingerprint);
            var index = IndexManager.DecryptIndexWithKey(encryptedIndex, aesKey);

            string prefix = index.CustomName ?? fingerprint;
            var decrypted = new List<byte[]>();
            for (int i = 0; i < index.FragentCount; i++)
            {
                string fname = $"{prefix}_{i}.rdrf";
                byte[] fileBytes = storage.ReadFragment(fname);
                var (_, data) = FragmentFileHeader.DecryptWithEmbeddedIndex(fileBytes, aesKey);
                // Strip ETN trailer from fragment data
                var (cleanData, _, _, _, _) = Fss6Etn.ParseTrailer(data);
                decrypted.Add(cleanData);
            }

            string tmpMergePath = Path.Combine(storageDir, $"merge_{Guid.NewGuid():N}.tmp");
            FragmentEngine.Frags.MergeFragents(decrypted, tmpMergePath);
            byte[] restored = File.ReadAllBytes(tmpMergePath);
            try { File.Delete(tmpMergePath); } catch { }
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
            index.Fss6FragentBlockMaps = null;
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

            // Strip trailer from first fragment
            var (rawData, _, _, _, _) = Fss6Etn.ParseTrailer(fragments[0]);
            fragments[0] = rawData; // no trailer

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
        var (data, _, _, _, _, _, _) = EtnTrailer.Parse(new byte[0]);
        Assert.Empty(data);
        _output.WriteLine("PASS: Empty trailer parse returns empty");

        var (data2, _, _, _, _, _, _) = EtnTrailer.Parse(new byte[] { 1, 2, 3 });
        Assert.Equal(3, data2.Length);
        _output.WriteLine("PASS: Small data without trailer returns data as>is");
    }

    [Fact]
    public void TrailersMatchAcrossAllFragments()
    {
        // All fragments must have identical index block maps in their trailers
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var (_, refIdxFlat, refIdxCnt, refRcFlat, refRcCnt) = Fss6Etn.ParseTrailer(fragments[0]);
            for (int i = 1; i < fragments.Count; i++)
            {
                var (_, idxFlat, idxCnt, rcFlat, rcCnt) = Fss6Etn.ParseTrailer(fragments[i]);
                Assert.True(EtnBlockMap.DiffTrimmed(refIdxFlat, refIdxCnt, idxFlat, idxCnt, EtnBlockMap.TrailerHashLen).Count == 0,
                    $"Fragment {i} index BM differs from fragment 0");
                Assert.True(EtnBlockMap.DiffTrimmed(refRcFlat, refRcCnt, rcFlat, rcCnt, EtnBlockMap.TrailerHashLen).Count == 0,
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
