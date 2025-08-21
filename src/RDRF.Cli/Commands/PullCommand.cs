using System.Security.Cryptography;
using System.Text;
using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PullCommand : Command
{
    public PullCommand() : base("pull", "Pull fragments and RC from storage backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var versionOpt = new Option<string?>("-v") { Description = "Version number or 'list'" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(versionOpt);
        Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var version = parseResult.GetValue(versionOpt);
            var pwd = parseResult.GetValue(passwordOpt);

            if (indexFile == null || !indexFile.Exists)
            {
                Console.Error.WriteLine("Error: index file not found");
                return 1;
            }

            byte[] password = DeployHelper.ResolvePassword(pwd != null ? Encoding.UTF8.GetBytes(pwd) : null);
            try { return await PullService.Run(indexFile.FullName, password, version); }
            finally { if (password.Length > 0) CryptographicOperations.ZeroMemory(password); }
        });
    }
}
