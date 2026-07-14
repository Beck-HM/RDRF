using System.IO;
using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

/// <summary>
/// MCP tool: read backup metadata from WPF UI.
/// </summary>

public class InfoTool : IMcpTool
{
    private readonly Func<string, bool> _sendIpc;

    public InfoTool(Func<string, bool> sendIpc) => _sendIpc = sendIpc;
    public string Name => "wpf_info";
    public string Description => "Show backup metadata by loading an index file in the RDRF desktop application";

    public Dictionary<string, object> InputSchema => new()
    {
        ["indexPath"] = new { type = "string", description = "Path to the .indrdrf index file" },
        ["password"] = new { type = "string", description = "Decryption password" },
    };

    public string[] Required => ["indexPath", "password"];

    public async Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        string indexPath = args.GetValueOrDefault("indexPath")?.ToString() ?? throw new ArgumentException("indexPath required");
        string password = args.GetValueOrDefault("password")?.ToString() ?? throw new ArgumentException("password required");

        // Wait for app to be ready, then navigate to Decrypt tab via UIA
        await Task.Delay(3000);
        await WpfElementFinder.ClickButton("TabDecrypt", 15000);
        await Task.Delay(500);

        // IPC: set index file path
        _sendIpc($@"{{""action"":""set_decrypt_path"",""value"":""{indexPath.Replace("\"", "\\\"")}""}}");
        await Task.Delay(200);

        // IPC: set password (triggers LoadDecryptInfo)
        _sendIpc($@"{{""action"":""set_decrypt_password"",""value"":""{password.Replace("\"", "\\\"")}""}}");
        await Task.Delay(1000);

        // IPC: read backup info from ViewModel (writes to temp file)
        _sendIpc($@"{{""action"":""read_backup_info""}}");
        await Task.Delay(500);

        // Read info from temp file
        string infoPath = Path.Combine(AppContext.BaseDirectory, "rdrf_TestOutput", "rdrf_info.json");
        string? json = null;
        for (int i = 0; i < 10; i++)
        {
            if (System.IO.File.Exists(infoPath))
            {
                json = System.IO.File.ReadAllText(infoPath);
                break;
            }
            await Task.Delay(500);
        }

        if (!string.IsNullOrEmpty(json))
            return json;

        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["file"] = "",
            ["size"] = "",
            ["strategy"] = "",
            ["fragments"] = "",
            ["created"] = "",
        }, new JsonSerializerOptions { WriteIndented = true });
    }
}

