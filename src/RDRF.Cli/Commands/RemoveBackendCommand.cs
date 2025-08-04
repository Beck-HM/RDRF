using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class RemoveBackendCommand : Command
{
    public RemoveBackendCommand() : base("remove", "Remove a backend configuration or delete a remote version")
    {
        var nameOpt = new Option<string?>("-name") { Description = "Backend name to remove" };
        var nodeOpt = new Option<bool>("-node") { Description = "Remove a backend from configuration" };

        Add(nameOpt);
        Add(nodeOpt);

        SetAction((ParseResult parseResult) =>
        {
            var name = parseResult.GetValue(nameOpt);
            bool node = parseResult.GetValue(nodeOpt);

            if (!node || string.IsNullOrEmpty(name))
            {
                Console.Error.WriteLine("Usage: rdrf remove -name <name> -node");
                return 1;
            }

            ConfigManager.RemoveBackend(name);
            Console.WriteLine($"Backend '{name}' removed from rdrf_config.yaml");
            return 0;
        });
    }
}
