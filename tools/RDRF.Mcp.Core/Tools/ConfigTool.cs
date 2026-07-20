using System.Text.Json;
using RDRF.Core.Configuration;

namespace RDRF.Mcp.Core.Tools;

public class ConfigTool : IMcpTool
{
    public string Name => "config";
    public string Description => "Show RDRF configuration (storage root, log level, auto-fp, default storage)";

    public Dictionary<string, object> InputSchema => new()
    {
        ["command"] = new { type = "string", description = "Subcommand: 'show' (default)" },
    };

    public string[] Required => [];

    public Task<string> ExecuteAsync(Dictionary<string, object?> args)
    {
        RdrfConfig.Initialize();
        GlobalConfig.Load();

        var result = new Dictionary<string, object?>
        {
            ["rdrfDirectory"] = RdrfConfig.RootDir,
            ["logDirectory"] = RdrfConfig.LogDir,
            ["logLevel"] = GlobalConfig.LogLevel,
            ["autoFp"] = GlobalConfig.AutoFp,
            ["defaultStorage"] = string.IsNullOrEmpty(GlobalConfig.DefaultStorage) ? "(not set)" : GlobalConfig.DefaultStorage,
        };
        return Task.FromResult(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }
}
