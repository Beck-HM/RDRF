using System.Text.Json;
using RDRF.Core.Encryption;
using RDRF.Core.Index;

namespace RDRF.Mcp.Core.Tools;

/// <summary>
/// MCP tool: show backup metadata.
/// </summary>

public class InfoTool : IMcpTool
{
    public string Name => "info";
    public string Description => "Show backup metadata from an index file";

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
        (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
        var index = IndexManager.DeserializeIndex(cbor);

        var result = new Dictionary<string, object?>
        {
            ["fingerprint"] = index.FileFingerprint,
            ["file"] = index.OriginalName,
            ["size"] = index.FileSize,
            ["strategy"] = index.FssStrategy,
            ["fragments"] = index.FragmentCount,
            ["originalFragments"] = index.OriginalFragmentCount,
            ["createdAt"] = DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt).ToString("O"),
            ["versionNumber"] = index.VersionNumber,
            ["versionCount"] = index.Versions?.Count ?? 0,
            ["hasEtn"] = index.HasFss6EtnData,
        };
        return Task.FromResult(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }
}

