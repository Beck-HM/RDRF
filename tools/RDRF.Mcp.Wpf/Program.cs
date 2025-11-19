using System.IO;
using System.Text.Json;
using RDRF.Mcp.Wpf;
using RDRF.Mcp.Wpf.Tools;

Console.Error.WriteLine("[rdrf-mcp-wpf] starting...");

// Determine path to RDRF.App.exe (same directory as this project's parent)
string appDir = AppContext.BaseDirectory;
string appExe = Path.Combine(appDir, "RDRF.App.exe");
if (!File.Exists(appExe))
{
    // Fallback: look relative to project directory (dev mode via dotnet run)
    appExe = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "RDRF.App",
        "bin", "Release", "net8.0-windows", "RDRF.App.exe"));
}
if (!File.Exists(appExe))
{
    // Try Debug build as fallback
    appExe = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "RDRF.App",
        "bin", "Debug", "net8.0-windows", "RDRF.App.exe"));
}
if (!File.Exists(appExe))
{
    Console.Error.WriteLine($"[rdrf-mcp-wpf] RDRF.App.exe not found");
    return;
}

var controller = new WpfAppController(appExe);
Func<string, bool> sendIpc = json => controller.SendIpcMessage(json);
var server = new McpServer();
server.RegisterTool(new LaunchTool(controller));
server.RegisterTool(new CloseTool(controller));
server.RegisterTool(new BackupTool(sendIpc));
server.RegisterTool(new RestoreTool(sendIpc));
server.RegisterTool(new InfoTool());

// JSON-RPC 2.0 over stdio, newline-delimited
await foreach (var json in ReadStdInAsync())
{
    try
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("method", out var methodEl))
        {
            string method = methodEl.GetString() ?? "";
            string? id = root.TryGetProperty("id", out var idEl) ? idEl.GetRawText() : null;

            if (method == "initialize")
            {
                WriteJson(new
                {
                    jsonrpc = "2.0",
                    id = id,
                    result = new
                    {
                        protocolVersion = "2024-11-05",
                        capabilities = new { tools = new { } },
                        serverInfo = new { name = "rdrf-mcp-wpf", version = "1.0.0" }
                    }
                });
            }
            else if (method == "tools/list")
            {
                var tools = server.ListTools();
                WriteJson(new { jsonrpc = "2.0", id = id, result = new { tools } });
            }
            else if (method == "tools/call")
            {
                var name = root.GetProperty("params").GetProperty("name").GetString() ?? "";
                var argsEl = root.GetProperty("params").GetProperty("arguments");
                var argsDict = JsonSerializer.Deserialize<Dictionary<string, object?>>(argsEl.GetRawText())
                    ?? new Dictionary<string, object?>();

                try
                {
                    var result = await server.CallToolAsync(name, argsDict);
                    WriteJson(new
                    {
                        jsonrpc = "2.0",
                        id = id,
                        result = new { content = new[] { new { type = "text", text = result } } }
                    });
                }
                catch (Exception ex)
                {
                    WriteJson(new
                    {
                        jsonrpc = "2.0",
                        id = id,
                        error = new { code = -32603, message = ex.Message }
                    });
                }
            }
            else if (id != null)
            {
                WriteJson(new
                {
                    jsonrpc = "2.0",
                    id = id,
                    error = new { code = -32601, message = $"Method not found: {method}" }
                });
            }
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[rdrf-mcp-wpf] error: {ex.Message}");
    }
}

static async IAsyncEnumerable<string> ReadStdInAsync()
{
    while (true)
    {
        var line = await Console.In.ReadLineAsync();
        if (line == null) yield break;
        if (string.IsNullOrWhiteSpace(line)) continue;
        yield return line;
    }
}

static void WriteJson(object obj)
{
    var json = JsonSerializer.Serialize(obj, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
    Console.Out.WriteLine(json);
    Console.Out.Flush();
}
