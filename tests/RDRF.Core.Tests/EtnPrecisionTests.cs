using RDRF.Core.FSS;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
/// <summary>
/// Phase 3 ?256>byte block-level precision tests.
/// Verifies that ETN can pinpoint exactly which 256>byte blocks are corrupted.
/// </summary>
public class EtnPrecisionTests
{
    private readonly ITestOutputHelper _output;

    public EtnPrecisionTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void CorruptByte0_Block0Identified()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments[0].Length > 256, "Fragment must be >256 bytes");

            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 0);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(0));
            Assert.Contains(0, result.CorruptedFragmentBlocks[0]);
            _output.WriteLine("PASS: Byte 0 - block 0");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptByte255_Block0Identified()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Byte 255 is the last byte of block 0 (0>indexed)
            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 255);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.Contains(0, result.CorruptedFragmentBlocks[0]);
            Assert.DoesNotContain(1, result.CorruptedFragmentBlocks[0]);
            _output.WriteLine("PASS: Byte 255 - block 0");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptByte256_Block1Identified()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Byte 256 is the first byte of block 1
            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 256);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.DoesNotContain(0, result.CorruptedFragmentBlocks[0]);
            Assert.Contains(1, result.CorruptedFragmentBlocks[0]);
            _output.WriteLine("PASS: Byte 256 - block 1");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptByte511_Block1Identified()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Byte 511 is the last byte of block 1
            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 511);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.DoesNotContain(0, result.CorruptedFragmentBlocks[0]);
            Assert.Contains(1, result.CorruptedFragmentBlocks[0]);
            _output.WriteLine("PASS: Byte 511 - block 1");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void CorruptByte512_Block2Identified()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 512);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.Contains(2, result.CorruptedFragmentBlocks[0]);
            Assert.DoesNotContain(1, result.CorruptedFragmentBlocks[0]);
            _output.WriteLine("PASS: Byte 512 - block 2");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void TwoSeparateBlocksInSameFragment()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments[0].Length > 512, "Fragment must be >512 bytes for 2>block test");

            // Corrupt byte 0 (block 0) and byte 256 (block 1)
            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 0);
            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 256);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.Contains(0, result.CorruptedFragmentBlocks[0]);
            Assert.Contains(1, result.CorruptedFragmentBlocks[0]);
            Assert.Equal(2, result.CorruptedFragmentBlocks[0].Count);
            _output.WriteLine($"PASS: 2 blocks corrupted in same fragment: [{string.Join(",", result.CorruptedFragmentBlocks[0])}]");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void DifferentFragments_DifferentBlocksIndependentlyReported()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments");

            fragments[0] = EtnTestHelpers.CorruptFragmentDataAt(fragments[0], 0);
            fragments[1] = EtnTestHelpers.CorruptFragmentDataAt(fragments[1], 256);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);
            Assert.Contains(0, result.CorruptedFragmentBlocks[0]);
            Assert.Contains(1, result.CorruptedFragmentBlocks[1]);
            _output.WriteLine("PASS: Independent block tracking across fragments");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void IndexRcFragment_AllBlockTypesIndependent()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments");

            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexJson);
            fragments[1] = EtnTestHelpers.CorruptFragmentData(fragments[1]);
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcJson);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, corruptedRc);
            Assert.False(result.IsValid);
            Assert.True(result.IndexCorrupted);
            Assert.NotEmpty(result.IndexCorruptedBlocks);
            Assert.True(result.RcCorrupted);
            Assert.NotEmpty(result.RcCorruptedBlocks);
            Assert.Contains(1, result.CorruptedFragments);
            Assert.True(result.CorruptedFragmentBlocks.ContainsKey(1));
            Assert.NotEmpty(result.CorruptedFragmentBlocks[1]);
            _output.WriteLine("PASS: Three independent block-level lists");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void RcCorruption_BlocksFlagged()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Corrupt RC content
            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcJson);

            var result = Fss6Etn.CrossValidate(indexJson, fragments, corruptedRc);
            Assert.True(result.RcCorrupted);
            Assert.NotEmpty(result.RcCorruptedBlocks);
            _output.WriteLine($"PASS: RC corruption: {result.RcCorruptedBlocks.Count} blocks");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void AllIntact_AllBlockListsEmpty()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexJson, fragments, rcJson, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            var result = Fss6Etn.CrossValidate(indexJson, fragments, rcJson);

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
}
