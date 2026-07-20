using RDRF.Core;
using RDRF.Core.DSAA;
using RDRF.Core.PasswordManager;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class EtiCommand : Command
{
    private readonly PasswordManager _passwordManager;

    public EtiCommand(PasswordManager passwordManager) : base("eti", "Export/Transfer/Import — move backup between storage directories")
    {
        _passwordManager = passwordManager;

        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var dstArg = new Argument<DirectoryInfo>("dstDir") { Description = "Destination storage directory" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };
        var fpOpt = new Option<string?>("-fp") { Description = "FastPassword key (use instead of -password)" };
        var dryRunOpt = new Option<bool>("--dry-run") { Description = "Preview without transferring" };
        var keepSourceOpt = new Option<bool>("--keep-source") { Description = "Keep source files after transfer (default: delete)" };
        var concurrencyOpt = new Option<int>("--concurrency") { Description = "Parallel fragment transfers (default: 1)" };

        Arguments.Add(indexArg);
        Arguments.Add(dstArg);
        Options.Add(passwordOpt);
        Options.Add(fpOpt);
        Options.Add(dryRunOpt);
        Options.Add(keepSourceOpt);
        Options.Add(concurrencyOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var dstDir = parseResult.GetValue(dstArg);
            var pwd = parseResult.GetValue(passwordOpt);
            var fpKey = parseResult.GetValue(fpOpt);
            bool dryRun = parseResult.GetValue(dryRunOpt);
            bool keepSource = parseResult.GetValue(keepSourceOpt);
            int concurrency = Math.Max(1, parseResult.GetValue(concurrencyOpt));

            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
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

            if (password.Length == 0) { AnsiConsole.MarkupLine("[red]Error: password cannot be empty.[/]"); return 1; }

            try
            {
                int exitCode = 0;
                await ProgressReporter.Run("Transferring", async progress =>
                {
                    exitCode = await TransferService.Run(
                        indexFile.FullName, password, dstDir.FullName,
                        dryRun, keepSource, concurrency, progress ?? null!);
                });
                return exitCode;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}
