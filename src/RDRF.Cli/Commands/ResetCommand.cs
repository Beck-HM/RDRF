using RDRF.Dssa;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class ResetCommand : Command
{
    public ResetCommand() : base("reset", "Update a backend configuration")
    {
        var nameOpt = new Option<string>("-name") { Description = "Current backend name" };
        var nodeOpt = new Option<bool>("-node") { Description = "Update a backend" };
        var argsArg = new Argument<string[]>("params") { Arity = ArgumentArity.ZeroOrMore };

        Add(nameOpt);
        Add(nodeOpt);
        Add(argsArg);

        SetAction((ParseResult parseResult) =>
        {
            var currentName = parseResult.GetValue(nameOpt);
            bool node = parseResult.GetValue(nodeOpt);
            var rawArgs = parseResult.GetValue(argsArg);

            if (!node || string.IsNullOrEmpty(currentName) || rawArgs == null || rawArgs.Length == 0)
            {
                Console.Error.WriteLine("Usage: rdrf reset -name <name> -node name:<new_name> & param:value & ...");
                return 1;
            }

            var joined = string.Join(" ", rawArgs);
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in joined.Split('&', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                int colon = part.IndexOf(':');
                if (colon < 0) continue;
                dict[part[..colon].Trim()] = part[(colon + 1)..].Trim();
            }

            if (!dict.ContainsKey("name"))
            {
                Console.Error.WriteLine("Error: 'name' parameter is required");
                return 1;
            }

            var existing = ConfigManager.Load().FirstOrDefault(b =>
                b.Name.Equals(currentName, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                Console.Error.WriteLine($"Error: backend '{currentName}' not found");
                return 1;
            }

            var entry = new BackendConfigEntry
            {
                Name = dict["name"],
                Type = existing.Type,
            };

            foreach (var kv in existing.Parameters)
                entry.Parameters[kv.Key] = kv.Value;
            foreach (var kv in dict)
                if (kv.Key != "name")
                    entry.Parameters[kv.Key] = kv.Value;

            ConfigManager.UpdateBackend(currentName, entry);
            Console.WriteLine($"Backend '{currentName}' updated to '{entry.Name}' in rdrf_config.yaml");
            return 0;
        });
    }
}
