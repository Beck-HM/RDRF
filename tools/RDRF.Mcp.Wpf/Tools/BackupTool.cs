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

        // IPC: set file path
        _sendIpc($@"{{""action"":""set_encrypt_path"",""value"":""{filePath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(200);

        // IPC: set password
        _sendIpc($@"{{""action"":""set_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(200);

        // UIA: click Encrypt tab (already should be active by default)
        // (UI automation for clicking Start button is available but may need
        //  foreground focus — consider starting encryption via future IPC action)

        var result = new
        {
            status = "data_sent",
            note = "File path and password sent to RDRF desktop. Click Start Encryption manually.",
            filePath,
            strategy
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
