using System.Text.Json;
using RDRF.Core.FragmentEngine;
using RDRF.Core.FSS;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.Integrity;
using RDRF.Core.DSAA;

namespace RDRF.Mcp.Core.Tools;

public class StatusTool : IMcpTool
{
    public string Name => "status";
    public string Description => "Check fragment integrity of a backup (fragment-level hash verification)";

    public Dictionary<string, object> InputSchema => new()
    {
        ["indexFile"] = new { type = "string", description = "Path to the .indrdrf index file" },
        ["password"] = new { type = "string", description = "Encryption password" },
    };

    public string[] Required => ["indexFile", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexFile = args.GetValueOrDefault("indexFile")?.ToString() ?? throw new ArgumentException("indexFile required");
        string? pwd = args.GetValueOrDefault("password")?.ToString();
        byte[] password = !string.IsNullOrEmpty(pwd)
            ? System.Text.Encoding.UTF8.GetBytes(pwd)
            : throw new ArgumentException("password required");

        if (!File.Exists(indexFile)) throw new FileNotFoundException($"Index file not found: {indexFile}");

        byte[] encryptedIndex = await File.ReadAllBytesAsync(indexFile);
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);
        string storageDir = Path.GetDirectoryName(Path.GetFullPath(indexFile))!;
        var storage = new RealLocalDSAA(storageDir);

        string prefix = index.CustomName ?? index.FileFingerprint;
        bool hasEtn = index.HasFss6EtnData;
        var fragments = new List<object>();
        int ok = 0, corrupted = 0, missing = 0;

        for (int i = 0; i < index.FragmentCount; i++)
        {
            int? rawSize = null;
            bool? hashMatch = null;
            string fragName = Frags.FragmentFilename(prefix, i);
            if (storage.FragmentExists(fragName))
            {
                byte[] frag = storage.ReadFragment(fragName);
                rawSize = frag.Length;
                if (index.FragmentHashes != null && i < index.FragmentHashes.Count)
                    hashMatch = IntegrityChecker.VerifyFragment(frag, index.FragmentHashes[i]);
                if (hashMatch == true) ok++; else corrupted++;
            }
            else { missing++; }

            fragments.Add(new { index = i, status = hashMatch == null ? "MISSING" : (hashMatch.Value ? "OK" : "CORRUPTED"), size = rawSize, hashMatch });
        }

        return JsonSerializer.Serialize(new
        {
            fingerprint = index.FileFingerprint,
            originalName = index.OriginalName,
            fileSize = index.FileSize,
            fssStrategy = index.FssStrategy + (hasEtn ? " + FSS6" : ""),
            compression = index.Compression,
            hasEtn,
            fragments,
            summary = new { total = index.FragmentCount, ok, corrupted, missing }
        }, new JsonSerializerOptions { WriteIndented = true });
    }
}

internal class RealLocalDSAA : LocalDSAAAdapter
{
    public RealLocalDSAA(string path) : base(path) { }
    public new bool FragmentExists(string path) => base.FragmentExists(path);
    public new byte[] ReadFragment(string path) => base.ReadFragment(path);
}
