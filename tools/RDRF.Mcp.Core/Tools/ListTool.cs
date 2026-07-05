using System.Text.Json;
using RDRF.Core;
using RDRF.Core.Encryption;
using RDRF.Core.Index;

namespace RDRF.Mcp.Core.Tools;

/// <summary>
/// MCP tool: list backups in a storage directory.
/// </summary>

public class ListTool : IMcpTool
{
    public string Name => "list";
    public string Description => "List all backups in a storage directory";

    public Dictionary<string, object> InputSchema => new()
    {
        ["storageDir"] = new { type = "string", description = "Storage directory path" },
        ["password"] = new { type = "string", description = "Encryption password (needed to read index metadata)" },
    };

    public string[] Required => ["storageDir"];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string storageDir = args.GetValueOrDefault("storageDir")?.ToString() ?? throw new ArgumentException("storageDir required");
        string? pwd = args.GetValueOrDefault("password")?.ToString();
        byte[]? password = !string.IsNullOrEmpty(pwd) ? System.Text.Encoding.UTF8.GetBytes(pwd) : null;

        if (!Directory.Exists(storageDir)) throw new DirectoryNotFoundException($"Directory not found: {storageDir}");

        var indexFiles = Directory.GetFiles(storageDir, "*" + Constants.IndexFileSuffix);
        var list = new List<Dictionary<string, object?>>();

        foreach (var f in indexFiles)
        {
            try
            {
                var info = new Dictionary<string, object?>
                {
                    ["fingerprint"] = Path.GetFileNameWithoutExtension(f),
                    ["path"] = f
                };

                if (password != null)
                {
                    byte[] encIdx = File.ReadAllBytes(f);
                    (_, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
                    var index = IndexManager.DeserializeIndex(cbor);
                    info["file"] = index.OriginalName;
                    info["size"] = index.FileSize;
                    info["strategy"] = index.FssStrategy;
                    info["versionNumber"] = index.VersionNumber;
                    info["fragments"] = index.FragmentCount;
                }

                list.Add(info);
            }
            catch
            {
                list.Add(new Dictionary<string, object?>
                {
                    ["fingerprint"] = Path.GetFileNameWithoutExtension(f),
                    ["path"] = f,
                    ["error"] = "Cannot decrypt (wrong password?)"
                });
            }
        }

        return Task.FromResult(JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
    }
}

