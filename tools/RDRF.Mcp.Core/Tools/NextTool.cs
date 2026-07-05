using System.Text.Json;
using RDRF.Core;
using RDRF.Core.Dssa;
using RDRF.Core.Versioning;

namespace RDRF.Mcp.Core.Tools;

/// <summary>
/// MCP tool: create incremental versioned backup.
/// </summary>

public class NextTool : IMcpTool
{
    public string Name => "next";
    public string Description => "Create an incremental versioned backup of a modified file";

    public Dictionary<string, object> InputSchema => new()
    {
        ["filePath"] = new { type = "string", description = "Path to the modified file" },
        ["storageDir"] = new { type = "string", description = "Storage directory (same as initial backup)" },
        ["message"] = new { type = "string", description = "Commit message describing the change" },
        ["password"] = new { type = "string", description = "Encryption password" },
    };

    public string[] Required => ["filePath", "storageDir", "message"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string filePath = args.GetValueOrDefault("filePath")?.ToString() ?? throw new ArgumentException("filePath required");
        string storageDir = args.GetValueOrDefault("storageDir")?.ToString() ?? throw new ArgumentException("storageDir required");
        string message = args.GetValueOrDefault("message")?.ToString() ?? throw new ArgumentException("message required");
        string? pwd = args.GetValueOrDefault("password")?.ToString();
        byte[] password = !string.IsNullOrEmpty(pwd)
            ? System.Text.Encoding.UTF8.GetBytes(pwd)
            : throw new ArgumentException("password required for incremental backup");

        if (!File.Exists(filePath)) throw new FileNotFoundException($"File not found: {filePath}");
        if (!Directory.Exists(storageDir)) throw new DirectoryNotFoundException($"Storage directory not found: {storageDir}");

        string fp = await VersionedBackup.BackupAsync(filePath, new LocalDssaAdapter(storageDir),
            password, message);

        var result = new Dictionary<string, object?>
        {
            ["fingerprint"] = fp,
            ["storageDir"] = Path.GetFullPath(storageDir),
            ["indexFile"] = $"{fp}.indrdrf"
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}

