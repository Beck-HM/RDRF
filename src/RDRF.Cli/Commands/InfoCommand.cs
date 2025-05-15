using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Cli.Services;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class InfoCommand : Command
{
    public InfoCommand() : base("info", "Show backup details from index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile");
        var passwordOpt = new Option<string?>("-password") { Description = "Password (skip interactive prompt)" };

        Arguments.Add(indexArg);
        Options.Add(passwordOpt);

        SetAction((ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);

            RdrfIndex index;
            try
            {
                index = RDRFEngine.DecryptIndex(encryptedIndex, password);
            }
            catch
            {
                Console.Error.WriteLine("Error: wrong password or corrupted index file");
                return 1;
            }

            string createdAt = DateTimeOffset.FromUnixTimeSeconds(index.CreatedAt)
                .ToString("yyyy-MM-dd HH:mm:ss UTC");

            Console.WriteLine($"Fingerprint: {index.FileFingerprint}");
            Console.WriteLine($"File:        {index.OriginalName}");
            Console.WriteLine($"Size:        {index.FileSize:N0} bytes");
            Console.WriteLine($"Strategy:    {index.FssStrategy}");
            Console.WriteLine($"Fragments:   {index.FragentCount} (original: {index.OriginalFragentCount})");

            string? fss6 = (index.Fss6FragentBlockMaps != null || index.Fss6RcBlockMap != null)
                ? "with FSS6/ETN" : null;
            Console.WriteLine($"ETN:         {(fss6 ?? "no")}");

            Console.WriteLine($"Salt:        {index.Salt ?? "(none)"}");
            Console.WriteLine($"Created:     {createdAt}");
            if (index.UpdatedAt.HasValue)
            {
                string updatedAt = DateTimeOffset.FromUnixTimeSeconds(index.UpdatedAt.Value)
                    .ToString("yyyy-MM-dd HH:mm:ss UTC");
                Console.WriteLine($"Updated:     {updatedAt}");
            }
            if (index.CustomName != null)
                Console.WriteLine($"CustomName:  {index.CustomName}");
            return 0;
        });
    }
}
