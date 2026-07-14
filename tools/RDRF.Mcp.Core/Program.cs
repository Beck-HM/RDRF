using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RDRF.Mcp.Core;
using RDRF.Mcp.Core.Tools;

Console.Error.WriteLine("[rdrf-mcp-core] starting...");

string? apiKey = Environment.GetEnvironmentVariable("RDRF_MCP_KEY");
if (string.IsNullOrEmpty(apiKey))
{
    apiKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    Console.Error.WriteLine("[rdrf-mcp-core] WARNING: RDRF_MCP_KEY not set, using ephemeral key");
    Console.Error.WriteLine("[rdrf-mcp-core] Set RDRF_MCP_KEY environment variable for persistent auth.");
}
else
{
    Console.Error.WriteLine("[rdrf-mcp-core] api-key auth enabled");
}

var server = new McpServer();
server.RegisterTool(new BackupTool());
server.RegisterTool(new RestoreTool());
server.RegisterTool(new InfoTool());
server.RegisterTool(new CheckTool());
server.RegisterTool(new VerifyTool());
server.RegisterTool(new ListTool());
server.RegisterTool(new NextTool());

// JSON-RPC 2.0 over stdio, newline-delimited
await foreach (var json in ReadStdInAsync())
{
    try
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Handle JSON-RPC request or notification
        if (root.TryGetProperty("method", out var methodEl))
        {
            string method = methodEl.GetString() ?? "";
            string? id = root.TryGetProperty("id", out var idEl) ? idEl.GetRawText() : null;

            if (method == "initialize")
            {
                var response = new
                {
                    jsonrpc = "2.0",
                    id = id,
                    result = new
                    {
                        protocolVersion = "2024-11-05",
                        capabilities = new
                        {
                            tools = new { }
                        },
                        serverInfo = new
                        {
                            name = "rdrf-mcp-core",
                            version = "1.0.0"
                        }
                    }
                };
                WriteJson(response);
            }
            else if (method == "tools/list")
            {
                var tools = server.ListTools();
                var response = new
                {
                    jsonrpc = "2.0",
                    id = id,
                    result = new { tools }
                };
                WriteJson(response);
            }
            else if (method == "tools/call")
            {
                // API key auth check (timing-safe comparison, only when env var is set)
                string? envKey = Environment.GetEnvironmentVariable("RDRF_MCP_KEY");
                if (!string.IsNullOrEmpty(envKey))
                {
                    string? requestKey = root.TryGetProperty("params", out var p) && p.TryGetProperty("apiKey", out var ak) ? ak.GetString() : null;
                    if (requestKey == null || !CryptographicOperations.FixedTimeEquals(
                        Encoding.UTF8.GetBytes(requestKey), Encoding.UTF8.GetBytes(envKey)))
                    {
                        if (id != null)
                            WriteJson(new { jsonrpc = "2.0", id = id, error = new { code = -32001, message = "Unauthorized: invalid or missing apiKey" } });
                        continue;
                    }
                }

                var name = root.GetProperty("params").GetProperty("name").GetString() ?? "";
                var argsEl = root.GetProperty("params").GetProperty("arguments");
                var argsDict = JsonSerializer.Deserialize<Dictionary<string, object?>>(argsEl.GetRawText())
                    ?? new Dictionary<string, object?>();

                try
                {
                    var result = await server.CallToolAsync(name, argsDict);
                    var response = new
                    {
                        jsonrpc = "2.0",
                        id = id,
                        result = new
                        {
                            content = new[]
                            {
                                new { type = "text", text = result }
                            }
                        }
                    };
                    WriteJson(response);
                }
                catch (Exception ex)
                {
                    var response = new
                    {
                        jsonrpc = "2.0",
                        id = id,
                        error = new { code = -32603, message = ex.Message }
                    };
                    WriteJson(response);
                }
            }
            else
            {
                if (id != null)
                {
                    var response = new
                    {
                        jsonrpc = "2.0",
                        id = id,
                        error = new { code = -32601, message = $"Method not found: {method}" }
                    };
                    WriteJson(response);
                }
            }
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[rdrf-mcp-core] error: {ex.Message}");
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
