using System.Text.Json;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using RDRF.Core.FSS;

namespace RDRF.Mcp.Core.Tools;

/// <summary>
/// MCP tool: run ETN cross-validation.
/// </summary>

public class VerifyTool : IMcpTool
{
    public string Name => "verify";
    public string Description => "Run ETN cross-validation on an FSS6 backup";

    public Dictionary<string, object> InputSchema => new()
    {
        ["indexPath"] = new { type = "string", description = "Path to the .indrdrf index file" },
        ["password"] = new { type = "string", description = "Encryption password" },
    };

    public string[] Required => ["indexPath", "password"];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexPath = args.GetValueOrDefault("indexPath")?.ToString() ?? throw new ArgumentException("indexPath required");
        string pwd = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");

        if (!File.Exists(indexPath)) throw new FileNotFoundException($"Index not found: {indexPath}");

        byte[] password = System.Text.Encoding.UTF8.GetBytes(pwd);
        byte[] encryptedIndex = File.ReadAllBytes(indexPath);
        (byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);

        if (!index.HasFss6EtnData)
            throw new InvalidOperationException("Backup does not contain FSS6/ETN data");

        string storageDir = Path.GetDirectoryName(indexPath)!;
        var storage = new LocalDSAAAdapter(storageDir);
        string prefix = index.CustomName ?? index.FileFingerprint;

        byte[] encryptedRc = storage.ReadRc(prefix);
        byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);

        var fragments = new List<byte[]>();
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
            if (!storage.FragmentExists(fname)) continue;
            byte[] encrypted = storage.ReadFragment(fname);
            byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);
            fragments.Add(decrypted);
        }

        byte[] indexBytes = IndexManager.SerializeIndex(index);
        var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);

        var response = new Dictionary<string, object?>
        {
            ["isValid"] = result.IsValid,
            ["fragmentsChecked"] = fragments.Count,
            ["totalFragments"] = index.FragmentCount,
            ["indexCorrupted"] = result.IndexCorrupted,
            ["rcCorrupted"] = result.RcCorrupted,
            ["corruptedFragments"] = result.CorruptedFragments.Count,
        };
        return Task.FromResult(JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = true }));
    }
}

