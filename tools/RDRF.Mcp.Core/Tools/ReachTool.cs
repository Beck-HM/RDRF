using System.Text.Json;
using RDRF.Core.Encryption;
using RDRF.Core.Index;

namespace RDRF.Mcp.Core.Tools;

public class ReachTool : IMcpTool
{
    public string Name => "reach";
    public string Description => "Scan a directory for RDRF backup indexes and return file info";

    public Dictionary<string, object> InputSchema => new()
    {
        ["path"] = new { type = "string", description = "Directory to scan for .indrdrf index files" },
        ["recursive"] = new { type = "boolean", description = "Search subdirectories recursively" },
        ["password"] = new { type = "string", description = "Password to decrypt indexes for metadata" },
    };

    public string[] Required => ["path"];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string path = args.GetValueOrDefault("path")?.ToString() ?? throw new ArgumentException("path required");
        bool recursive = args.GetValueOrDefault("recursive") is bool r && r;
        string? pwd = args.GetValueOrDefault("password")?.ToString();
        byte[]? password = !string.IsNullOrEmpty(pwd) ? System.Text.Encoding.UTF8.GetBytes(pwd) : null;

        if (!Directory.Exists(path)) throw new DirectoryNotFoundException($"Directory not found: {path}");

        var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var indexFiles = Directory.GetFiles(path, "*.indrdrf", searchOption);
        var results = new List<object>();

        foreach (var idxPath in indexFiles)
        {
            var info = new Dictionary<string, object?>
            {
                ["path"] = Path.GetFullPath(idxPath),
                ["name"] = Path.GetFileName(idxPath),
                ["size"] = new FileInfo(idxPath).Length,
                ["lastWrite"] = File.GetLastWriteTime(idxPath).ToString("o"),
            };

            if (password != null)
            {
                try
                {
                    byte[] enc = File.ReadAllBytes(idxPath);
                    (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(enc, password);
                    var index = IndexManager.DeserializeIndex(cbor);
                    info["fingerprint"] = index.FileFingerprint;
                    info["originalName"] = index.OriginalName;
                    info["fileSize"] = index.FileSize;
                    info["fssStrategy"] = index.FssStrategy;
                    info["fragmentCount"] = index.FragmentCount;
                    info["compression"] = index.Compression;
                    info["versionNumber"] = index.VersionNumber;
                    info["hasEtn"] = index.HasFss6EtnData;
                }
                catch { info["decryptError"] = true; }
            }

            results.Add(info);
        }

        var result = new Dictionary<string, object?>
        {
            ["directory"] = Path.GetFullPath(path),
            ["count"] = results.Count,
            ["backups"] = results,
        };
        return Task.FromResult(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }
}
