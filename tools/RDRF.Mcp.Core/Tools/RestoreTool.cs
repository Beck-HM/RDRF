using System.Text.Json;
using RDRF.Core;
using RDRF.Core.Dssa;
using RDRF.Core.Versioning;

namespace RDRF.Mcp.Core.Tools;

public class RestoreTool : IMcpTool
{
    public string Name => "restore";
    public string Description => "Restore a backup from its index file";

    public Dictionary<string, object> InputSchema => new()
    {
        ["indexPath"] = new { type = "string", description = "Path to the .indrdrf index file" },
        ["outputPath"] = new { type = "string", description = "Output file path for restored data" },
        ["password"] = new { type = "string", description = "Encryption password" },
        ["version"] = new { type = "number", description = "Version number to restore (default: latest)" },
    };

    public string[] Required => ["indexPath", "outputPath", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexPath = args.GetValueOrDefault("indexPath")?.ToString() ?? throw new ArgumentException("indexPath required");
        string outputPath = args.GetValueOrDefault("outputPath")?.ToString() ?? throw new ArgumentException("outputPath required");
        string pwd = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");
        int? version = args.GetValueOrDefault("version") is JsonElement je && je.ValueKind == JsonValueKind.Number ? je.GetInt32() : null;

        if (!File.Exists(indexPath)) throw new FileNotFoundException($"Index not found: {indexPath}");
        byte[] password = System.Text.Encoding.UTF8.GetBytes(pwd);

        bool success;
        if (version.HasValue)
        {
            var records = VersionedRestore.GetVersionHistory(indexPath, password);
            var vr = records.FirstOrDefault(r => r.Version == version.Value)
                ?? throw new ArgumentException($"Version {version} not found");
            string storageDir = Path.GetDirectoryName(indexPath)!;
            string fp = Path.GetFileNameWithoutExtension(indexPath);
            using var engine = new RDRFEngine((byte[])password.Clone(), new LocalDssaAdapter(storageDir));
            string prefix = vr.FileFingerprint;
            success = await engine.RestoreFileFromFragmentsAsync(prefix, outputPath);
        }
        else
        {
            success = VersionedRestore.Restore(outputPath, indexPath, password);
        }

        if (!success) throw new InvalidOperationException("Restore failed (data may be corrupted)");

        var result = new { outputPath = Path.GetFullPath(outputPath), size = new FileInfo(outputPath).Length };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
