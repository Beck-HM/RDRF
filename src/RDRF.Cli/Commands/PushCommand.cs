using System.Security.Cryptography;
using System.Text;
using RDRF.Core;
using RDRF.Storage;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PushCommand : Command
{
    public PushCommand() : base("push", "Push fragments and RC to storage backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (INSECURE: visible in process list; omit for secure prompt)" };
        var dryRunOpt = new Option<bool>("--dry-run") { Description = "Preview what would be pushed without uploading" };
        var concurrencyOpt = new Option<int>("--concurrency");
        concurrencyOpt.Description = "Number of parallel uploads (default: 1)";

        Add(indexArg);
        Add(passwordOpt);
        Add(dryRunOpt);
        Add(concurrencyOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);
            bool dryRun = parseResult.GetValue(dryRunOpt);
            int concurrency = parseResult.GetValue(concurrencyOpt);

            if (indexFile == null || !indexFile.Exists)
            {
                Console.Error.WriteLine("Error: index file not found");
                return 1;
            }

            byte[] password = DeployHelper.ResolvePassword(pwd != null ? Encoding.UTF8.GetBytes(pwd) : null);

            try
            {
                if (dryRun)
                    return await PushService.Run(indexFile.FullName, password, dryRun: true);

                int exitCode = 0;
                await ProgressReporter.Run("Pushing to backends", async progress =>
                {
                    exitCode = await PushService.Run(indexFile.FullName, password,
                        dryRun: false, concurrency: concurrency, progress: progress);
                });
                return exitCode;
            }
            finally
            {
                if (password.Length > 0)
                    CryptographicOperations.ZeroMemory(password);
            }
        });
    }
}
