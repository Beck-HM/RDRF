namespace RDRF.Mcp.Wpf.Tools;

public class CloseTool : IMcpTool
{
    private readonly WpfAppController _controller;

    public CloseTool(WpfAppController controller) => _controller = controller;
    public string Name => "wpf_close";
    public string Description => "Close the RDRF desktop application";
    public Dictionary<string, object> InputSchema => new();
    public string[] Required => [];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        _controller.Close();
        return Task.FromResult("RDRF application closed");
    }
}
