using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

public class InfoTool : IMcpTool
{
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

        // Click Decrypt tab to see file info
        await WpfElementFinder.ClickButton("TabDecrypt", 5000);

        // Set index file to trigger info display
        await WpfElementFinder.SetText("DecryptIndexPath", indexPath);

        // Set password to decrypt info
        await WpfElementFinder.SetText("DecryptKeyBox", password);

        // Read info fields
        await Task.Delay(2000); // wait for UI to update

        var fileName = await WpfElementFinder.GetText("InfoFileName", 3000);
        var fileSize = await WpfElementFinder.GetText("InfoFileSize", 3000);
        var strategy = await WpfElementFinder.GetText("InfoStrategy", 3000);
        var fragmentCount = await WpfElementFinder.GetText("InfoFragmentCount", 3000);
        var created = await WpfElementFinder.GetText("InfoCreated", 3000);

        var result = new Dictionary<string, object?>
        {
            ["file"] = fileName,
            ["size"] = fileSize,
            ["strategy"] = strategy,
            ["fragments"] = fragmentCount,
            ["created"] = created,
        };
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }
}
