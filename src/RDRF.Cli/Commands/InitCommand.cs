using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class InitCommand : Command
{
    public InitCommand() : base("init", "Initialize an RDRF storage backend")
    {
        var restOpt = new Option<string>("-rest") { Description = "Initialize a REST API backend (name:... & api_url:... & token:...)" };
        var keyOpt = new Option<string>("-key") { Description = "Initialize an S3-compatible KEY backend (name:... & endpoint:... & bucket:... & access_key:... & secret_key:...)" };
        var pathOpt = new Option<string>("-path") { Description = "Initialize a PATH backend (name:... & base_path:...)" };

        Add(restOpt);
        Add(keyOpt);
        Add(pathOpt);

        SetAction((ParseResult parseResult) =>
        {
            var rest = parseResult.GetValue(restOpt);
            var key = parseResult.GetValue(keyOpt);
            var path = parseResult.GetValue(pathOpt);

            int count = (rest != null ? 1 : 0) + (key != null ? 1 : 0) + (path != null ? 1 : 0);
            if (count != 1)
            {
                Console.Error.WriteLine("Error: exactly one of -rest, -key, or -path must be specified");
                return 1;
            }

            string? type = null;
            string? rawArgs = null;
            if (rest != null) { type = "rest"; rawArgs = rest; }
            else if (key != null) { type = "key"; rawArgs = key; }
            else if (path != null) { type = "path"; rawArgs = path; }

            var entry = ParseEntry(type!, rawArgs!);
            if (entry == null)
            {
                Console.Error.WriteLine("Error: invalid parameters. Usage:");
                Console.Error.WriteLine($"  -rest name:<n> & api_url:<url> & token:<t>");
                Console.Error.WriteLine($"  -key  name:<n> & endpoint:<e> & bucket:<b> & access_key:<k> & secret_key:<s>");
                Console.Error.WriteLine($"  -path name:<n> & base_path:<p>");
                return 1;
            }

            ConfigManager.AddBackend(entry);
            Console.WriteLine($"Backend '{entry.Name}' ({type}) added to rdrf_config.yaml");
            return 0;
        });
    }

    private static BackendConfigEntry? ParseEntry(string type, string raw)
    {
        var parts = raw.Split('&', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var part in parts)
        {
            int colon = part.IndexOf(':');
            if (colon < 0) continue;
            var key = part[..colon].Trim();
            var val = part[(colon + 1)..].Trim();
            dict[key] = val;
        }

        if (!dict.ContainsKey("name"))
            return null;

        var entry = new BackendConfigEntry
        {
            Name = dict["name"],
            Type = type,
        };

        switch (type)
        {
            case "rest":
                if (!dict.ContainsKey("api_url") || !dict.ContainsKey("token"))
                    return null;
                entry.Parameters["api_url"] = dict["api_url"];
                entry.Parameters["token"] = dict["token"];
                break;
            case "key":
                if (!dict.ContainsKey("endpoint") || !dict.ContainsKey("bucket") ||
                    !dict.ContainsKey("access_key") || !dict.ContainsKey("secret_key"))
                    return null;
                entry.Parameters["endpoint"] = dict["endpoint"];
                entry.Parameters["bucket"] = dict["bucket"];
                entry.Parameters["access_key"] = dict["access_key"];
                entry.Parameters["secret_key"] = dict["secret_key"];
                if (dict.TryGetValue("region", out var r)) entry.Parameters["region"] = r;
                break;
            case "path":
                if (!dict.ContainsKey("base_path"))
                    return null;
                entry.Parameters["base_path"] = dict["base_path"];
                break;
        }

        return entry;
    }
}
