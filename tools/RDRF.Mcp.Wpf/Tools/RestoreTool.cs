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
        string? outputPath = args.GetValueOrDefault("outputPath")?.ToString();

        // Click Decrypt tab
        await WpfElementFinder.ClickButton("TabDecrypt", 5000);

        // Send index path to WPF app via IPC
        _sendIpc($@"{{""action"":""set_decrypt_path"",""value"":""{indexPath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(500);

        // Send decrypt password via IPC
        _sendIpc($@"{{""action"":""set_decrypt_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(300);

        // Click Start Decryption
        await WpfElementFinder.ClickButton("StartDecryptButton", 5000);

        // Wait for completion
        string? stageText = null;
        for (int i = 0; i < 60; i++)
        {
            await Task.Delay(5000);
            stageText = await WpfElementFinder.GetText("DecryptStageText", 3000);
            if (stageText == null || stageText.Contains("Complete", StringComparison.OrdinalIgnoreCase))
                break;
        }

        var result = new
        {
            status = stageText?.Contains("Complete") == true ? "success" : "unknown",
            stage = stageText,
            indexPath
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
