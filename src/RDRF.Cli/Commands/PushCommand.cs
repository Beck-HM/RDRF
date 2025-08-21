using System.Security.Cryptography;
using System.Text;
using RDRF.Storage;
using System.CommandLine;

namespace RDRF.Cli.Commands;

public class PushCommand : Command
{
    public PushCommand() : base("push", "Push fragments and RC to storage backends")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password (INSECURE: visible in process list; omit for secure prompt)" };

        Add(indexArg);
        Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (indexFile == null || !indexFile.Exists)
            {
                Console.Error.WriteLine("Error: index file not found");
                return 1;
            }

            byte[] password = DeployHelper.ResolvePassword(pwd != null ? Encoding.UTF8.GetBytes(pwd) : null);
            try { return await PushService.Run(indexFile.FullName, password); }
            finally { if (password.Length > 0) CryptographicOperations.ZeroMemory(password); }
        });
    }
}
