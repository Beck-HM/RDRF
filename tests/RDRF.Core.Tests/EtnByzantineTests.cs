using RDRF.Core.FSS;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

[Collection("EtnSerial")]
/// <summary>
/// Phase 2 - Byzantine arbitration / triangular consensus tests.
/// When two or three nodes disagree, ETN must use majority and cross-references
/// to determine which node(s) are actually corrupted.
/// </summary>
public class EtnByzantineTests
{
    private readonly ITestOutputHelper _output;

    public EtnByzantineTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void IndexCorrupted_RcAndTrailersAgreeOnTruth()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] corruptedIndex = EtnTestHelpers.CorruptIndexNonEtnFields(indexBytes);

            var result = Fss6Etn.CrossValidate(corruptedIndex, fragments, rcBytes);
            Assert.True(result.IndexCorrupted, "Index must be flagged");
            Assert.False(result.RcCorrupted, "RC must not be flagged");
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: Index corrupted, RC + trailers agree - correct diagnosis");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void RcCorrupted_IndexAndTrailersAgreeOnTruth()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] corruptedRc = EtnTestHelpers.CorruptRcContent(rcBytes);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, corruptedRc);
            Assert.True(result.RcCorrupted, "RC must be flagged");
            Assert.False(result.IndexCorrupted, "Index must not be flagged");
            Assert.Empty(result.CorruptedFragments);
            _output.WriteLine("PASS: RC corrupted, Index + trailers agree - correct diagnosis");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void SingleFragmentCorrupted_IndexAndRcAgree()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments");

            fragments[0] = EtnTestHelpers.CorruptFragmentData(fragments[0]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.False(result.IsValid);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.Single(result.CorruptedFragments);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine("PASS: Single fragment corrupted, Index + RC agree");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void TwoFragmentsCorrupted_BothFlagged()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 4, "Need at least 4 fragments");

            fragments[0] = EtnTestHelpers.CorruptFragmentData(fragments[0]);
            fragments[3] = EtnTestHelpers.CorruptFragmentData(fragments[3]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.Contains(0, result.CorruptedFragments);
            Assert.Contains(3, result.CorruptedFragments);
            Assert.Equal(2, result.CorruptedFragments.Count);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine("PASS: Two fragments corrupted, both flagged, index + RC clean");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void AllThreeCorrupted_AllFlagged()
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
            _output.WriteLine("PASS: All three nodes corrupted - all flagged");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void ThreeWayDisagreementOnFragment_FragmentFlagged()
    {
        // Scenario: actual fragment differs from BOTH index and RC claims,
        // but index and RC agree with each other - fragment is the liar
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);
            Assert.True(fragments.Count >= 2, "Need at least 2 fragments");

            fragments[1] = EtnTestHelpers.CorruptFragmentData(fragments[1]);

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.Contains(1, result.CorruptedFragments);
            Assert.False(result.IndexCorrupted);
            Assert.False(result.RcCorrupted);
            _output.WriteLine("PASS: Index + RC agree, fragment differs - fragment flagged");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void FragmentTrailerCorrupted_TrailerFlaggedDataNot()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            // Corrupt the trailer's Index BM section in fragment[0]
            // Trailer format: [rawSize(4)][fragBmCount(4)][fragFlat(2×N)][indexBmCount(4)][indexFlat(2×N)][...]
            byte[] corrupted = (byte[])fragments[0].Clone();
            int trailerSize = BitConverter.ToInt32(corrupted, corrupted.Length - 4);
            int trailerStart = corrupted.Length - trailerSize;
            int idxCount = BitConverter.ToInt32(corrupted, trailerStart + 4);
            if (idxCount > 0)
            {
                int idx2BStart = trailerStart + 8;
                int flipPos = idx2BStart + (idxCount - 1) * 2;
                corrupted[flipPos] ^= 0xFF;
            }
            fragments[0] = corrupted;

            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);
            Assert.DoesNotContain(0, result.CorruptedFragments);
            _output.WriteLine("PASS: Trailer corruption - trailer flagged, data not");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }

    [Fact]
    public void IndexEtnFieldsCorrupted_IndexItselfNotFlagged()
    {
        string storageDir = EtnTestHelpers.CreateStorageDir();
        try
        {
            var (indexBytes, fragments, rcBytes, _, _) = EtnTestHelpers.CreateDecryptedBackup(storageDir);

            byte[] corrupted = EtnTestHelpers.CorruptIndexEtnFields(indexBytes);

            var result = Fss6Etn.CrossValidate(corrupted, fragments, rcBytes);
            Assert.False(result.IndexCorrupted,
                "ETN field corruption must not flag IndexCorrupted (fields stripped before hash)");
            _output.WriteLine("PASS: ETN fields in index corrupted - index not flagged");
        }
        finally
        {
            EtnTestHelpers.Cleanup(storageDir);
        }
    }
}
