using System.Security.Cryptography;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Storage;
using RDRF.Core.ETN;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
public class EtnCrossValidationTests
{
    private readonly ITestOutputHelper _output;

    public EtnCrossValidationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void AllIntact_ReturnsValid()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.True(result.IsValid,
                $"Expected valid, got: IndexCorrupted{result.IndexCorrupted}, " +
                $"RcCorrupted{result.RcCorrupted}, " +
                $"Fragments[{string.Join(",", result.CorruptedFragments)}]");
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: AllIntact baseline");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptIndex_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexBytes);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, rcBytes);
            Assert.True(result.IndexCorrupted, "Index corruption not detected");
            Assert.False(result.RcCorrupted, "RC should not be flagged");
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: Index corruption detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptFirstFragment_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            fragments[0] = EtnTestHelpers.CorruptFragmentData(fragments[0]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.False(result.IndexCorrupted, "Index should not be flagged");
            Assert.False(result.RcCorrupted, "RC should not be flagged");
            _output.WriteLine("PASS: Fragment[0] corruption detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptMiddleFragment_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 3, "Need at least 3 fragments for this test");
            int target = fragments.Count / 2;
            fragments[target] = EtnTestHelpers.CorruptFragmentData(fragments[target]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(target, result.CorruptedFragments);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine($"PASS: Fragment[{target}] corruption detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptLastFragment_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            int last = fragments.Count - 1;
            fragments[last] = EtnTestHelpers.CorruptFragmentData(fragments[last]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(last, result.CorruptedFragments);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine($"PASS: Fragment[{last}] corruption detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptMultipleFragments_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 4, "Need at least 4 fragments for this test");

            fragments[0] = EtnTestHelpers.CorruptFragmentData(fragments[0]);
            fragments[3] = EtnTestHelpers.CorruptFragmentData(fragments[3]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.Contains(3, result.CorruptedFragments);
            Assert.Equal(2, result.CorruptedFragments.Count);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine("PASS: Multiple fragment corruptions detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptRcFile_Detected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcBytes);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, corruptedRc);
            Assert.False(result.IsValid);
            Assert.True(result.RcCorrupted, "RC corruption not detected");
            Assert.False(result.IndexCorrupted, "Index should not be flagged");
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: RC corruption detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptAllThree_AllDetected()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments for this test");

            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexBytes);
            fragments[1] = EtnTestHelpers.CorruptFragmentData(fragments[1]);
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcBytes);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, corruptedRc);
            Assert.False(result.IsValid);
            Assert.True(result.IndexCorrupted, "Index corruption not detected");
            Assert.True(result.RcCorrupted, "RC corruption not detected");
            Assert.Contains(1, result.CorruptedFragments);
            _output.WriteLine("PASS: All three corruptions detected");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptFragmentTrailer_FragmentItselfNotFlagged()
    {
        // Trailer stores cross-references for Index + RC. Corrupting a byte in the trailer's
        // indexBM hashes section should NOT cause the fragment's own data to be flagged,
        // but IndexCorrupted will be true (index BM in trailer no longer matches actual index).
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] corrupted = (byte[])fragments[0].Clone();
            int trailerSize = BitConverter.ToInt32(corrupted, corrupted.Length - 4);
            int trailerStart = corrupted.Length - trailerSize;
            int fragBmCount = BitConverter.ToInt32(corrupted, trailerStart + 4);
            int idxBmCntPos = trailerStart + 8 + fragBmCount * 2;
            int indexBMCount = BitConverter.ToInt32(corrupted, idxBmCntPos);
            int idxFlatStart = idxBmCntPos + 4;
            if (indexBMCount > 0)
            {
                int flipPos = idxFlatStart + (indexBMCount - 1) * 2;
                corrupted[flipPos] ^= 0xFF;
            }

            fragments[0] = corrupted;

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            // Fragment 0 should NOT be in CorruptedFragments (data is intact, only trailer corrupted)
            Assert.DoesNotContain(0, result.CorruptedFragments);
            // But Index may be flagged because trailer's indexBM cross-reference is corrupted
            _output.WriteLine($"PASS: Fragment[0] not flagged (IndexCorrupted{result.IndexCorrupted}, " +
                $"RcCorrupted{result.RcCorrupted}, Fragments[{string.Join(",", result.CorruptedFragments)}])");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptIndexEtnField_IndexItselfNotFlagged()
    {
        // ETN metadata fields (fss6_fragment_block_maps, fss6_rc_block_map) are stripped
        // before computing the index block map. Corrupting them must NOT cause IndexCorrupted.
        // (Fragments or RC may still be flagged because their cross-references are wrong.)
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] corrupted = EtnTestHelpers.CorruptIndexEtnFields(indexBytes);

            var result = Fss6Etn.CrossValidate(corrupted, fragments, rcBytes);
            Assert.False(result.IndexCorrupted,
                "ETN field corruption must not flag IndexCorrupted (fields stripped before hash)");
            _output.WriteLine("PASS: Index not flagged (RcCorrupted" + result.RcCorrupted +
                ", FragmentsW" + string.Join(",", result.CorruptedFragments) + "])");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptRcButRecomputeTrailer_Detected()
    {
        // Scenario: RC file is corrupted, but fragment trailers still have correct RC block maps.
        // This tests trailers as the cross-reference for RC validation.
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Corrupt content in RC JSON (preserving JSON structure)
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcBytes);

            // But keep index and fragments intact (they still have the original RC block maps)
            var result = Fss6Etn.CrossValidate(indexBytes, fragments, corruptedRc);
            Assert.False(result.IsValid);
            Assert.True(result.RcCorrupted,
                "RC corruption must be detected even when index+fragments are intact");
            Assert.False(result.IndexCorrupted);
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: RC corruption detected via trailer cross-reference");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
// ---------- //  Precision block-level tests (256B granularity)
    // 
    [Fact]
    public void AllIntact_AllBlockListsEmpty()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);

            Assert.True(result.IsValid);
            Assert.Empty(result.IndexCorruptedBlocks);
            Assert.Empty(result.RcCorruptedBlocks);
            Assert.Empty(result.CorruptedFragmentBlocks);
            Assert.Empty(result.CorruptedFragmentTrailers);
            _output.WriteLine("PASS: All block-level lists empty on intact backup");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptIndex_BlockIndicesPopulated()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexBytes);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, rcBytes);
            Assert.True(result.IndexCorrupted, "Index must be flagged");
            Assert.NotEmpty(result.IndexCorruptedBlocks);
            Assert.Empty(result.RcCorruptedBlocks);
            Assert.Empty(result.CorruptedFragmentBlocks);
            _output.WriteLine($"PASS: Index corrupted, {result.IndexCorruptedBlocks.Count} blocks identified");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptFragment_BlockIndicesPopulated()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Corrupt fragment[0] at data.Length/2, record the raw data length for block calc
            var (rawData, _, _, _, _) = Fss6Etn.ParseTrailer(fragments[0]);
            int targetPos = rawData.Length / 2;
            var idx = IndexManager.DeserializeIndex(indexBytes);
            int blockSize = EtnBlockMap.GetBlockSize(idx.FileSize);
            int expectedBlock = targetPos / blockSize;
            _output.WriteLine($"  Fragment[0] ra[{rawData.Length}, flip @ {targetPos}, expected block ~{expectedBlock}");

            fragments[0] = EtnTestHelpers.CorruptFragmentData(fragments[0]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(0),
                "Must have block-level details for fragment 0");
            Assert.NotEmpty(result.CorruptedFragmentBlocks[0]);
            Assert.Contains(expectedBlock, result.CorruptedFragmentBlocks[0]);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine($"PASS: Fragment[0] corrupted, block {expectedBlock} identified");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptFragment_CorrectBlockRange()
    {
        // Corrupt at a known byte to verify block index math.
        // Flip byte 0 in fragment data - block 0 must be in the list.
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            int bs = EtnBlockMap.GetBlockSize(IndexManager.DeserializeIndex(indexBytes).FileSize);

            var (rawData, _, _, _, _) = Fss6Etn.ParseTrailer(fragments[0]);
            Assert.True(rawData.Length > bs, $"Fragment must be >{bs} bytes for this test");

            byte[] copy = (byte[])fragments[0].Clone();
            copy[0] ^= 0xFF; // corrupt byte 0 - block 0
            fragments[0] = copy;

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(0));
            Assert.Contains(0, result.CorruptedFragmentBlocks[0]);

            // Also corrupt a byte at offset bs - block 1
            copy = (byte[])fragments[1].Clone();
            copy[bs] ^= 0xFF;
            fragments[1] = copy;

            result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.Contains(1, result.CorruptedFragments);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(1));
            Assert.Contains(1, result.CorruptedFragmentBlocks[1]);

            _output.WriteLine("PASS: Block 0 and block 1 correctly identified at their exact positions");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptTrailer_CorruptedFragmentTrailersPopulated()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Corrupt the trailer's indexBM section in fragment[0]
            // Trailer format: [rawSize(4)][fragBmCount(4)][fragFlat(2×N)][indexBmCount(4)][indexFlat(2×N)][...]
            byte[] corrupted = (byte[])fragments[0].Clone();
            int trailerSize = BitConverter.ToInt32(corrupted, corrupted.Length - 4);
            int trailerStart = corrupted.Length - trailerSize;
            int fragBmCount = BitConverter.ToInt32(corrupted, trailerStart + 4);
            int idxBmCntPos = trailerStart + 8 + fragBmCount * 2;
            int indexBMCount = BitConverter.ToInt32(corrupted, idxBmCntPos);
            int idxFlatStart = idxBmCntPos + 4;
            if (indexBMCount > 0)
            {
                int flipPos = idxFlatStart + (indexBMCount - 1) * 2; // first byte of last index hash
                corrupted[flipPos] ^= 0xFF;
            }

            fragments[0] = corrupted;

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.Contains(0, result.CorruptedFragmentTrailers);
            Assert.DoesNotContain(0, result.CorruptedFragments);
            _output.WriteLine($"PASS: Fragment[0] trailer flagged: {string.Join(",", result.CorruptedFragmentTrailers)}");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptAllThree_AllBlockListsPopulated()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments");

            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexBytes);
            fragments[1] = EtnTestHelpers.CorruptFragmentData(fragments[1]);
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcBytes);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, corruptedRc);
            Assert.False(result.IsValid);
            Assert.True(result.IndexCorrupted);
            Assert.True(result.RcCorrupted);
            Assert.Contains(1, result.CorruptedFragments);

            Assert.NotEmpty(result.IndexCorruptedBlocks);
            Assert.NotEmpty(result.RcCorruptedBlocks);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(1));
            Assert.NotEmpty(result.CorruptedFragmentBlocks[1]);

            _output.WriteLine($"PASS: All block lists populated - Index:{result.IndexCorruptedBlocks.Count} " +
                $"RC:{result.RcCorruptedBlocks.Count} Frag[1]:{result.CorruptedFragmentBlocks[1].Count}");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
// ---------- //  Phase 0 - RC file encryption
    // 
    [Fact]
    public void RcFile_IsEncryptedOnDisk()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, fingerprint, rcCode) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var storage = new LocalFileAdapter(storageDir);
            byte[] onDisk = storage.ReadRc(fingerprint);

            // Encrypted RC should not equal plaintext
            Assert.NotEqual(rcBytes, onDisk);
            Assert.True(onDisk.Length > rcBytes.Length,
                "Encrypted RC should be larger than plaintext (nonce + ciphertext + tag)");
            _output.WriteLine($"PASS: RC file on disk is encrypted ({onDisk.Length} bytes vs {rcBytes.Length} bytes plaintext)");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void RcFile_WrongKey_FailsToDecrypt()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, fingerprint, rcCode) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            var storage = new LocalFileAdapter(storageDir);
            byte[] encryptedRc = storage.ReadRc(fingerprint);

            byte[] wrongKey = new byte[32];
            RandomNumberGenerator.Fill(wrongKey);

            byte[] decrypted = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, wrongKey);
            Assert.ThrowsAny<Exception>(() =>
                RDRF.Core.Storage.RcFile.FromCbor(decrypted));
            _output.WriteLine("PASS: Wrong key produces invalid CBOR");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void RcFile_TamperedOnDisk_FailsDecrypt()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, fingerprint, rcCode) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] aesKey = EncryptionLayer.DeriveKey(rcCode);
            var storage = new LocalFileAdapter(storageDir);
            byte[] encryptedRc = storage.ReadRc(fingerprint);

            // Flip one byte in the encrypted blob
            encryptedRc[5] ^= 0xFF;
            storage.WriteRc(fingerprint, encryptedRc);

            // Re-read and attempt decrypt - tampering produces garbage
            byte[] tampered = storage.ReadRc(fingerprint);
            byte[] decrypted = EncryptionLayer.DecryptFragmentWithKey(tampered, aesKey);
            Assert.ThrowsAny<Exception>(() =>
                RDRF.Core.Storage.RcFile.FromCbor(decrypted));
            _output.WriteLine("PASS: Tampered RC file rejected by CBOR parsing");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void RcFile_PlaintextCbor_StillParses()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            // Direct CBOR (no encryption) should still parse
            var plainRc = new RcFile { Version = 1, FileFingerprint = "test" };
            byte[] cbor = plainRc.ToCborBytes();

            var rc = RcFile.FromCbor(cbor);
            Assert.Equal(1, rc.Version);
            _output.WriteLine("PASS: Plaintext RC file parses correctly");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
}
