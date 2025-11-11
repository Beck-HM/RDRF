using System.Text.Json;
using RDRF.Core.Versioning;

namespace RDRF.Mcp.Core.Tools;

public class CheckTool : IMcpTool
{
    public string Name => "check";
    public string Description => "Show version history for a versioned backup";

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
        var records = VersionedRestore.GetVersionHistory(indexPath, password);

        var list = records.Select(r => new
        {
            version = r.Version,
            message = r.UserMessage,
            createdAt = DateTimeOffset.FromUnixTimeSeconds(r.CreatedAt).ToString("O"),
            files = r.Files?.Select(f => new { path = f.Path, change = f.ChangeType }).ToList()
        }).ToList();

        return Task.FromResult(JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
    }
}
