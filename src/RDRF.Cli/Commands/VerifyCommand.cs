using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

/// <summary>
/// Run ETN cross-validation on FSS6.x backups. CLI: rdrf verify.
/// </summary>

public class VerifyCommand : Command
{
    public VerifyCommand() : base("verify", "Run ETN cross-validation on FSS6 backup via index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (INSECURE: visible in process list; omit for secure prompt)" };

        Arguments.Add(indexArg);
        Options.Add(passwordOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);

            if (!indexFile.Exists)
            {
                AnsiConsole.MarkupLine($"[red]Error: index file not found: {indexFile.FullName.EscapeMarkup()}[/]");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            if (password.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Error: password is required. Use -password <pass> or run interactively.[/]");
                return 1;
            }
            try
            {
                byte[] encryptedIndex = await File.ReadAllBytesAsync(indexFile.FullName);

                RdrfIndex index;
                byte[] aesKey;
                try
                {
                    (aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                    index = IndexManager.DeserializeIndex(cbor);
                }
                catch
                {
                    AnsiConsole.MarkupLine("[red]Error: wrong password or corrupted index file[/]");
                    return 1;
                }

                if (index.Fss6FragmentBlockMaps == null && index.Fss6RcBlockMap == null)
                {
                    AnsiConsole.MarkupLine("[red]Error: backup does not contain FSS6/ETN data - verification requires FSS6[/]");
                    return 1;
                }

                string storageDir = indexFile.DirectoryName!;
                var storage = new LocalDSAAAdapter(storageDir);
                string prefix = index.CustomName ?? index.FileFingerprint;

            byte[] encryptedRc = storage.ReadRc(prefix);
            byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);

            var fragments = new List<byte[]>();
            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (!storage.FragmentExists(fname)) continue;

                    byte[] encrypted = storage.ReadFragment(fname);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);

                fragments.Add(decrypted);
            }

            byte[] indexBytes = IndexManager.SerializeIndex(index);
            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);

            var infoTable = new Table();
            infoTable.Border(TableBorder.Rounded);
            infoTable.AddColumn("Property");
            infoTable.AddColumn(new TableColumn("Value").NoWrap());
            string fp = index.FileFingerprint;
            infoTable.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
            infoTable.AddRow("Strategy", $"{index.FssStrategy} + FSS6");
            infoTable.AddRow("Fragments", $"{fragments.Count}/{index.FragmentCount} available");
            AnsiConsole.Write(infoTable);
            AnsiConsole.WriteLine();

            if (result.IsValid)
            {
                AnsiConsole.MarkupLine("[green]Status: VALID[/]");
                return 0;
            }

            AnsiConsole.MarkupLine("[red]Status: CORRUPTED[/]");
            AnsiConsole.WriteLine();

            var statusTable = new Table();
            statusTable.Border(TableBorder.Rounded);
            statusTable.AddColumn("Component");
            statusTable.AddColumn("Status");
            statusTable.AddColumn("Details");

            string idxStatus = result.IndexCorrupted
                ? $"[red]CORRUPTED[/] ({result.IndexCorruptedBlocks.Count} blocks{FormatBlockList(result.IndexCorruptedBlocks).EscapeMarkup()})"
                : "[green]OK[/]";
            statusTable.AddRow("Index", "", idxStatus);

            string rcStatus = result.RcCorrupted
                ? $"[red]CORRUPTED[/] ({result.RcCorruptedBlocks.Count} blocks{FormatBlockList(result.RcCorruptedBlocks).EscapeMarkup()})"
                : "[green]OK[/]";
            statusTable.AddRow("RC", "", rcStatus);

            if (result.CorruptedFragments.Count > 0)
            {
                string fragDetail = $"[red]{result.CorruptedFragments.Count}/{fragments.Count}[/]";
                foreach (int fi in result.CorruptedFragments.OrderBy(x => x))
                {
                    var blocks = result.CorruptedFragmentBlocks.ContainsKey(fi)
                        ? result.CorruptedFragmentBlocks[fi]
                        : new List<int>();
                    fragDetail += $"\n  Fragment {fi}: {blocks.Count} blocks {FormatBlockList(blocks).EscapeMarkup()}";
                }
                statusTable.AddRow("Fragments", "", fragDetail);
            }
            else
                statusTable.AddRow("Fragments", "", "[green]OK[/]");

            if (result.CorruptedFragmentTrailers.Count > 0)
            {
                string trailers = string.Join(",", result.CorruptedFragmentTrailers.OrderBy(x => x));
                statusTable.AddRow("Trailers", "", $"[red]corrupted: [{trailers.EscapeMarkup()}][/]");
            }

            AnsiConsole.Write(statusTable);

            int totalCorrupted = result.IndexCorruptedBlocks.Count + result.RcCorruptedBlocks.Count
                + (result.CorruptedFragmentBlocks?.Values.Sum(v => v.Count) ?? 0);
            int suspicious = result.SuspiciousFragmentBlocks?.Values.Sum(v => v.Count) ?? 0;
            if (suspicious > 0)
                AnsiConsole.MarkupLine($"[yellow]Suspicious (non-fatal): {suspicious} blocks with hash mismatch in only one source[/]");
            if (totalCorrupted == 0 && suspicious == 0)
                AnsiConsole.MarkupLine("[green]All nodes validated successfully.[/]");

            return 1;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static string FormatBlockList(List<int> blocks)
    {
        if (blocks.Count == 0) return "";
        var sample = blocks.Take(5).ToList();
        string s = " [" + string.Join(", ", sample);
        if (blocks.Count > 5) s += ", ...";
        s += "]";
        return s;
    }
}







