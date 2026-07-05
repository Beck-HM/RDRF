namespace RDRF.Mcp.Core;

/// <summary>
/// MCP tool registry and IMcpTool interface.
/// </summary>

public class McpServer
{
    private readonly Dictionary<string, IMcpTool> _tools = new();

    public void RegisterTool(IMcpTool tool) => _tools[tool.Name] = tool;

    public List<object> ListTools()
    {
        return _tools.Values.Select(t => new
        {
            name = t.Name,
            description = t.Description,
            inputSchema = new
            {
                type = "object",
                properties = t.InputSchema,
                required = t.Required
            }
        }).Cast<object>().ToList();
    }

    public async Task<string> CallToolAsync(string name, Dictionary<string, object?> args)
    {
        if (!_tools.TryGetValue(name, out var tool))
            throw new ArgumentException($"Tool not found: {name}");
        return await tool.ExecuteAsync(args);
    }
}

/// <summary>
/// MCP tool registry and IMcpTool interface.
/// </summary>

public interface IMcpTool
{
    string Name { get; }
    string Description { get; }
    Dictionary<string, object> InputSchema { get; }
    string[] Required { get; }
    Task<string> ExecuteAsync(Dictionary<string, object?> args);
}

