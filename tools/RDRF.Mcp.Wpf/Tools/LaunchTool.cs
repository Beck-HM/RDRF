using System.Text.Json;

namespace RDRF.Mcp.Wpf.Tools;

public class LaunchTool : IMcpTool
{
    private readonly WpfAppController _controller;

    public LaunchTool(WpfAppController controller) => _controller = controller;
    public string Name => "wpf_launch";
    public string Description => "Launch the RDRF desktop application";
    public Dictionary<string, object> InputSchema => new();
    public string[] Required => [];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        var proc = _controller.Launch();
        var result = new { pid = proc.Id, processName = proc.ProcessName };
        return Task.FromResult(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }
}
