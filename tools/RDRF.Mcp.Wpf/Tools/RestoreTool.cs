using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

public class RestoreTool : IMcpTool
{
    private readonly Func<string, bool> _sendIpc;

    public RestoreTool(Func<string, bool> sendIpc) => _sendIpc = sendIpc;
    public string Name => "wpf_restore";
    public string Description => "Restore a backup using the RDRF desktop application UI";

    public Dictionary<string, object> InputSchema => new()
    {
        ["indexPath"] = new { type = "string", description = "Path to the .indrdrf index file" },
        ["password"] = new { type = "string", description = "Decryption password" },
        ["outputPath"] = new { type = "string", description = "Output path for restored file" },
    };

    public string[] Required => ["indexPath", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexPath = args.GetValueOrDefault("indexPath")?.ToString() ?? throw new ArgumentException("indexPath required");
        string password = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");

        // IPC: set index path and password
        _sendIpc($@"{{""action"":""set_decrypt_path"",""value"":""{indexPath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(200);
        _sendIpc($@"{{""action"":""set_decrypt_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(200);

        // IPC: trigger decryption
        _sendIpc($@"{{""action"":""start_decrypt""}}");

        // Single UIA read to confirm decryption started
        await Task.Delay(2000);
        string? stageText = await WpfElementFinder.GetTextOnce("DecryptStageText", 3000);
        if (string.IsNullOrEmpty(stageText))
            stageText = await WpfElementFinder.GetTextOnce("DecryptPercentText", 2000);

        var result = new
        {
            status = "started",
            stage = stageText ?? "decrypting",
            indexPath
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
