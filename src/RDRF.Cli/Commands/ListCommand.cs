using RDRF.Dssa;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class ListCommand : Command
{
    public ListCommand() : base("list", "List configured backends or registered projects")
    {
        var nodeOpt = new Option<bool>("-node") { Description = "List all configured storage backends" };

        Add(nodeOpt);

        SetAction((ParseResult parseResult) =>
        {
            bool node = parseResult.GetValue(nodeOpt);

            if (!node)
            {
                Console.Error.WriteLine("Error: -node is required");
                return 1;
            }

            var backends = ConfigManager.Load();
            if (backends.Count == 0)
            {
                Console.WriteLine("No backends configured. Use 'rdrf init -rest/-key/-path' to add one.");
                return 0;
            }

            Console.WriteLine($"Configured backends ({backends.Count}):");
            Console.WriteLine();
            foreach (var b in backends)
            {
                string info = b.Type switch
                {
                    "rest" => $"api_url: {b.Parameters.GetValueOrDefault("api_url", "-")}",
                    "key" => $"endpoint: {b.Parameters.GetValueOrDefault("endpoint", "-")}, bucket: {b.Parameters.GetValueOrDefault("bucket", "-")}",
                    "path" => $"base_path: {b.Parameters.GetValueOrDefault("base_path", "-")}",
                    _ => b.Type,
                };
                Console.WriteLine($"  {b.Name,-15} ({b.Type,-5}) {info}");
            }

            return 0;
        });
    }
}
