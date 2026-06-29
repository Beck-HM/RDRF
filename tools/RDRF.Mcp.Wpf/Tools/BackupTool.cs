using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

public class BackupTool : IMcpTool
{
    private readonly Func<string, bool> _sendIpc;

    public BackupTool(Func<string, bool> sendIpc) => _sendIpc = sendIpc;
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

        // IPC: set strategy, file path, password, then trigger
        _sendIpc($@"{{""action"":""set_strategy"",""value"":""{strategy}""}}");
        await Task.Delay(200);
        _sendIpc($@"{{""action"":""set_encrypt_path"",""value"":""{filePath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(150);
        _sendIpc($@"{{""action"":""set_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(150);

        // IPC: trigger encryption — WPF app runs it in background thread
        _sendIpc($@"{{""action"":""start_encrypt""}}");

        // Wait briefly for confirmation that encryption started (1-shot UIA check)
        await Task.Delay(2000);
        string? stageText = await WpfElementFinder.GetTextOnce("EncryptStageText", 3000);
        if (string.IsNullOrEmpty(stageText))
            stageText = await WpfElementFinder.GetTextOnce("EncryptPercentText", 2000);

        var result = new
        {
            status = "started",
            stage = stageText ?? "encrypting",
            filePath,
            strategy
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
