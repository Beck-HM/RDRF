using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.PasswordManager;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class RescueCommand : Command
{
    private readonly PasswordManager _passwordManager;

    public RescueCommand(PasswordManager passwordManager) : base("resc", "Rescue backup from fragments without index file")
    {
        _passwordManager = passwordManager;

        var dirArg = new Argument<DirectoryInfo>("fragmentsDir") { Description = "Directory containing .rdrf fragment files" };
        var outputOpt = new Option<FileInfo>("-o") { Description = "Output file path (required)" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };
        var fpOpt = new Option<string?>("-fp") { Description = "FastPassword key (use instead of -password)" };

        Arguments.Add(dirArg);
        Options.Add(outputOpt);
        Options.Add(passwordOpt);
        Options.Add(fpOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var fragDir = parseResult.GetValue(dirArg);
            var output = parseResult.GetValue(outputOpt);
            var pwd = parseResult.GetValue(passwordOpt);
            var fpKey = parseResult.GetValue(fpOpt);

            if (!fragDir.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: fragments directory not found: {fragDir.FullName.EscapeMarkup()}[/]");
                return 1;
            }
            if (output == null)
            {
                AnsiConsole.MarkupLine("[red]Error: -o <outputPath> is required[/]");
                return 1;
            }

            // Find fragment 0 files to detect backup fingerprints
            var fragFiles = fragDir.GetFiles("*_0.rdrf");
            if (fragFiles.Length == 0)
            {
                // Try without index suffix in filename
                var allFrags = fragDir.GetFiles("*.rdrf");
                var byPrefix = allFrags.GroupBy(f =>
                {
                    var name = f.Name;
                    int lastUnderscore = name.LastIndexOf('_');
                    return lastUnderscore > 0 ? name[..lastUnderscore] : null;
                }).Where(g => g.Key != null).ToList();

                if (byPrefix.Count == 0)
                {
                    AnsiConsole.MarkupLine("[red]Error: no fragment files found in directory.[/]");
                    return 1;
                }

                var table = new Table { Border = TableBorder.Rounded };
                table.AddColumn("Fingerprint prefix");
                table.AddColumn("Fragments");
                foreach (var group in byPrefix.OrderByDescending(g => g.Count()))
                    table.AddRow(group.Key![..Math.Min(16, group.Key.Length)] + "…", group.Count().ToString());
                AnsiConsole.Write(table);
                AnsiConsole.MarkupLine($"[yellow]Found {byPrefix.Count} potential backup(s). Use a specific fragment 0 file with 'rdrf res' if you have the index.[/]");
                return 1;
            }

            if (fragFiles.Length > 1)
            {
                AnsiConsole.MarkupLine($"[yellow]Multiple backups found ({fragFiles.Length}). Using first: {fragFiles[0].Name}[/]");
            }

            byte[] password;
            if (fpKey != null)
            {
                string? stored = _passwordManager.GetByKey(fpKey);
                if (stored == null) { AnsiConsole.MarkupLine($"[red]FastPassword '{fpKey}' not found.[/]"); return 1; }
                password = Encoding.UTF8.GetBytes(stored);
            }
            else if (pwd != null)
            {
                password = Encoding.UTF8.GetBytes(pwd);
            }
            else
            {
                password = PasswordProvider.ReadInteractive();
            }

            if (password.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: password cannot be empty.[/]");
                return 1;
            }

            try
            {
                // Extract fingerprint from first fragment 0 filename
                string frag0Name = fragFiles[0].Name;
                int usIdx = frag0Name.LastIndexOf('_');
                string filePrefix = usIdx > 0 ? frag0Name[..usIdx] : frag0Name;

                var storage = new LocalDSAAAdapter(fragDir.FullName);
                int exitCode = await AnsiConsole.Status()
                    .StartAsync("Rescuing...", async _ =>
                    {
                        using var engine = new RDRFEngine(password, storage);
                        bool ok = await engine.RestoreFileFromFragmentsAsync(filePrefix, output.FullName);
                        return ok ? 0 : 1;
                    });

                if (exitCode == 0)
                {
                    AnsiConsole.MarkupLine($"[green]Rescued to:[/] {output.FullName.EscapeMarkup()}");
                    return 0;
                }
                AnsiConsole.MarkupLine("[red]Error: rescue failed (verify password and fragment integrity)[/]");
                return 1;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}
