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
        ["outputPath"] = new { type = "string", description = "Optional custom output path" },
    };

    public string[] Required => ["indexPath", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexPath = args.GetValueOrDefault("indexPath")?.ToString() ?? throw new ArgumentException("indexPath required");
        string password = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");
        string? outputPath = args.GetValueOrDefault("outputPath")?.ToString();

        // Navigate to Decrypt tab via UIA (retry with fallback)
        if (!await WpfElementFinder.ClickButton("TabDecrypt", 10000))
            await WpfElementFinder.ClickByText("Decrypt", 5000);

        // IPC: set index file path
        _sendIpc($@"{{""action"":""set_decrypt_path"",""value"":""{indexPath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(100);

        // IPC: set output path (optional)
        if (!string.IsNullOrEmpty(outputPath))
        {
            _sendIpc($@"{{""action"":""set_decrypt_output_path"",""value"":""{outputPath.Replace("\"", "\\\"")}""}}");
            await Task.Delay(100);
        }

        // IPC: set password
        _sendIpc($@"{{""action"":""set_decrypt_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(100);

        // IPC: start decrypt
        _sendIpc($@"{{""action"":""start_decrypt""}}");

        // UIA: read status
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
