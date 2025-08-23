using System.Security.Cryptography;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.FSS;
using RDRF.Core.Dssa;
using Xunit;

namespace RDRF.Core.Tests;

[CollectionDefinition("EtnSerial", DisableParallelization = true)]
public class EtnSerialCollectionDefinition { }

public static class EtnTestHelpers
{
    public static string TestFile
    {
        get
        {
            var dir = AppContext.BaseDirectory;
            for (int i = 0; i < 5; i++)
                dir = Path.GetDirectoryName(dir)!;
            return Path.Combine(dir, "1.mp4");
        }
    }

    public static string TestOutputDir =>
        Path.Combine(Path.GetDirectoryName(TestFile)!, "RDRF_TestOutput");

    public static string CreateStorageDir()
    {
        string dir = Path.Combine(TestOutputDir, $"ETN_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Cleanup(string storageDir)
    {
        try
        {
            if (Directory.Exists(storageDir))
                Directory.Delete(storageDir, recursive: true);
        }
        catch { }
    }

    public static (byte[] IndexBytes, List<byte[]> Fragments, byte[] RcBytes, string Fingerprint, byte[] RcCode)
        CreateDecryptedBackup(string storageDir, string strategy = "FSS6")
    {
        byte[] rcCode = EncryptionLayer.GenerateRcCode(32);
        byte[] rcCodeClone = (byte[])rcCode.Clone();
        var storage = new LocalDssaAdapter(storageDir);

        string fingerprint;
        using (var engine = new RDRFEngine(rcCode, storage))
        {
            fingerprint = engine.BackupFile(TestFile, strategy);
        }

        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, byte[] indexCbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, rcCodeClone);
        var index = IndexManager.DeserializeIndex(indexCbor);

        // Fragment encryption uses the same AES key as the index (no separate fragment key)
        string prefix = index.CustomName ?? fingerprint;
        var fragments = new List<byte[]>();
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fragFilename = $"{prefix}_{i}.rdrf";
            byte[] fragFileBytes = storage.ReadFragment(fragFilename);
            var (_, fragmentData, _) = FragmentFileHeader.DecryptWithEmbeddedIndex(fragFileBytes, aesKey);
            fragments.Add(fragmentData);
        }

        byte[] encryptedRc = storage.ReadRc(fingerprint);
        byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);

        byte[] indexBytes = IndexManager.SerializeIndex(index);

        return (indexBytes, fragments, rcBytes, fingerprint, rcCodeClone);
    }

    public static byte[] CorruptRcContent(byte[] rcBytes)
    {
        var rc = RcFile.FromCbor(rcBytes);
        rc.Version = 999;
        return rc.ToCborBytes();
    }

    public static byte[] CorruptFragmentData(byte[] fragmentWithTrailer)
    {
        var (data, _, _, _, _) = Fss6Etn.ParseTrailer(fragmentWithTrailer);
        if (data.Length == 0)
            throw new InvalidOperationException("Cannot corrupt empty fragment data");

        byte[] copy = (byte[])fragmentWithTrailer.Clone();
        int targetPos = data.Length / 2;
        copy[targetPos] ^= 0xFF;
        return copy;
    }

    public static byte[] CorruptFragmentDataAt(byte[] fragmentWithTrailer, int dataOffset)
    {
        var (data, _, _, _, _) = Fss6Etn.ParseTrailer(fragmentWithTrailer);
        if (data.Length == 0 || dataOffset > data.Length)
            throw new InvalidOperationException($"Invalid corruption offset {dataOffset} (data length {data.Length})");

        byte[] copy = (byte[])fragmentWithTrailer.Clone();
        copy[dataOffset] ^= 0xFF;
        return copy;
    }

    public static byte[] CorruptIndexNonEtnFields(byte[] indexBytes)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        index.OriginalName = index.OriginalName + "_CORRUPTED";
        return IndexManager.SerializeIndex(index);
    }

    public static byte[] CorruptIndexEtnFields(byte[] indexBytes)
    {
        var index = IndexManager.DeserializeIndex(indexBytes);
        index.Fss6FragmentBlockMaps = new List<List<string>> { new List<string> { "AA" } };
        return IndexManager.SerializeIndex(index);
    }

    public static byte[] CorruptRcFileOnDisk(string storageDir, string fingerprint, byte[] rcCode)
    {
        var storage = new LocalDssaAdapter(storageDir);
        byte[] encryptedIndex = storage.ReadIndex(fingerprint);
        (byte[] aesKey, _) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, rcCode);
        byte[] encryptedRc = storage.ReadRc(fingerprint);
        byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);
        byte[] corrupted = CorruptRcContent(rcBytes);
        byte[] reEncrypted = EncryptionLayer.EncryptFragmentWithKey(corrupted, aesKey);
        storage.WriteRc(fingerprint, reEncrypted);
        return reEncrypted;
    }

    public static void EnsureOutputDirExists()
    {
        if (!Directory.Exists(TestOutputDir))
            Directory.CreateDirectory(TestOutputDir);
    }
}
