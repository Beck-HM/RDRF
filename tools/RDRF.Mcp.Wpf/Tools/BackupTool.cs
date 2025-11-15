using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

public class BackupTool : IMcpTool
{
    public string Name => "wpf_backup";
    public string Description => "Backup a file using the RDRF desktop application UI";

    public Dictionary<string, object> InputSchema => new()
    {
        ["filePath"] = new { type = "string", description = "Full path to the file to backup" },
        ["strategy"] = new { type = "string", description = "FSS strategy (FSS1, FSS3, FSS6, FSS6.1, etc.)" },
        ["password"] = new { type = "string", description = "Encryption password" },
        ["fragmentSize"] = new { type = "number", description = "Fragment size in MB (default: 1)" },
        ["customName"] = new { type = "string", description = "Optional custom name for the backup" },
    };

    public string[] Required => ["filePath", "strategy", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string filePath = args.GetValueOrDefault("filePath")?.ToString() ?? throw new ArgumentException("filePath required");
        string strategy = args.GetValueOrDefault("strategy")?.ToString() ?? throw new ArgumentException("strategy required");
        string password = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");
        int? fragSize = args.GetValueOrDefault("fragmentSize") is JsonElement je && je.ValueKind == JsonValueKind.Number ? je.GetInt32() : null;
        string? customName = args.GetValueOrDefault("customName")?.ToString();

        // Click Encrypt tab if not already active
        await WpfElementFinder.ClickButton("TabEncrypt", 5000);

        // Set file path
        await WpfElementFinder.SetText("EncryptFilePath", filePath);

        // Set password
        await WpfElementFinder.SetText("EncryptKeyBox", password);

        // Set fragment size if specified
        if (fragSize.HasValue)
            await WpfElementFinder.SetText("FragmentSizeMB", fragSize.Value.ToString());

        // Set custom name if specified
        if (!string.IsNullOrEmpty(customName))
            await WpfElementFinder.SetText("CustomNameBox", customName);

        // Select strategy card
        await WpfElementFinder.ClickButton("Strategy" + strategy.Replace(".", "").Replace("+", "P"), 5000);

        // Click Start Encryption
        await WpfElementFinder.ClickButton("StartEncryptButton", 5000);

        // Wait for completion (up to 5 min)
        string? stageText = null;
        for (int i = 0; i < 60; i++)
        {
            await Task.Delay(5000);
            stageText = await WpfElementFinder.GetText("EncryptStageText", 3000);
            if (stageText == null || stageText.Contains("Complete", StringComparison.OrdinalIgnoreCase))
                break;
        }

        var result = new
        {
            status = stageText?.Contains("Complete") == true ? "success" : "unknown",
            stage = stageText,
            filePath,
            strategy
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
