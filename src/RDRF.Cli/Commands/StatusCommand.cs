using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Dssa;
using RDRF.Core.Encryption;
using RDRF.Core.Integrity;
using RDRF.Cli.Services;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class StatusCommand : Command
{
    public StatusCommand() : base("status", "Show per-fragment status and integrity for a backup")
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
            try
            {
                if (password.Length == 0)
                {
                    AnsiConsole.MarkupLine("[red]Error: password cannot be empty[/]");
                    return 1;
                }
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

                string storageDir = indexFile.DirectoryName!;
                var storage = new LocalDssaAdapter(storageDir);
                string prefix = index.CustomName ?? index.FileFingerprint;
                string lookupKey = index.CustomName ?? index.FileFingerprint;

            bool indexOk = storage.IndexExists(lookupKey);
            bool rcOk = storage.RcExists(lookupKey);
            if (rcOk)
            {
                try
                {
                    byte[] encryptedRc = storage.ReadRc(lookupKey);
                    EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);
                }
                catch { rcOk = false; }
            }

            bool hasEtn = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;

            var infoTable = new Table();
            infoTable.Border(TableBorder.Rounded);
            infoTable.AddColumn("Property");
            infoTable.AddColumn(new TableColumn("Value").NoWrap());
            string fp = index.FileFingerprint;
            infoTable.AddRow("Fingerprint", fp.Length > 32 ? $"{fp[..12]}...{fp[^8..]}" : fp);
            infoTable.AddRow("File", index.OriginalName);
            infoTable.AddRow("Strategy", index.FssStrategy + (hasEtn ? " + FSS6" : ""));
            AnsiConsole.Write(infoTable);
            AnsiConsole.WriteLine();

            var infraTable = new Table();
            infraTable.Border(TableBorder.Rounded);
            infraTable.AddColumn("Component");
            infraTable.AddColumn("Status");
            string indexStatus = indexOk ? "[green]OK[/]" : "[yellow]MISSING[/]";
            string rcStatus = rcOk ? "[green]OK[/]" : (storage.RcExists(lookupKey) ? "[yellow]ENCRYPTED[/]" : "[yellow]MISSING[/]");
            infraTable.AddRow("Index", indexStatus);
            infraTable.AddRow("RC", rcStatus);
            AnsiConsole.Write(new Panel(infraTable).Header("Backup Infrastructure").BorderColor(Color.Grey));
            AnsiConsole.WriteLine();

            int ok = 0, corrupted = 0, missing = 0;
            var rows = new List<(int idx, string status, string size, string hash)>();

            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (!storage.FragmentExists(fname))
                {
                    rows.Add((i, "[yellow]MISSING[/]", "-", "-"));
                    missing++;
                    continue;
                }

                try
                {
                    byte[] encrypted = storage.ReadFragment(fname);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);

                    if (hasEtn)
                    {
                        decrypted = RDRF.Core.ETN.EtnTrailer.Parse(decrypted).RawData;
                        if (index.Fss61RepairB != null)
                            decrypted = RDRF.Core.FSS.Fss61RepairTrailer.Parse(decrypted).data;
                        if (index.Fss62RepairB != null)
                            decrypted = RDRF.Core.FSS.Fss62RepairTrailer.Parse(decrypted).data;
                    }

                    string actualHash = IntegrityChecker.HashBytes(decrypted);
                    string expectedHash = index.FragmentHashes.Count > i ? index.FragmentHashes[i] : "";
                    bool match = IntegrityChecker.VerifyHash(actualHash, expectedHash);

                    string sizeStr = index.OriginalFragmentSizes.Count > i
                        ? FormatSize(index.OriginalFragmentSizes[i]) : FormatSize(decrypted.Length);

                    if (match)
                    {
                        rows.Add((i, "[green]OK[/]", sizeStr, "\u2705"));
                        ok++;
                    }
                    else
                    {
                        rows.Add((i, hasEtn ? "[yellow]ENCRYPTED[/]" : "[red]CORRUPTED[/]", sizeStr, "\u274C"));
                        corrupted++;
                    }
                }
                catch
                {
                    rows.Add((i, "[yellow]ENCRYPTED[/]", "-", "-"));
                    corrupted++;
                }
            }

            var fragmentTable = new Table();
            fragmentTable.Border(TableBorder.Rounded);
            fragmentTable.AddColumn(new TableColumn("#").RightAligned());
            fragmentTable.AddColumn("Status");
            fragmentTable.AddColumn("Size");
            fragmentTable.AddColumn("Hash");
            foreach (var r in rows)
                fragmentTable.AddRow(r.idx.ToString(), r.status, r.size, r.hash);
            AnsiConsole.Write(new Panel(fragmentTable).Header($"Fragment Status ({index.FragmentCount} expected)").BorderColor(Color.Grey));
            AnsiConsole.WriteLine();

            string summary = ok == index.FragmentCount
                ? $"[green]{ok}/{index.FragmentCount} OK[/]"
                : $"[green]{ok} OK[/], [red]{corrupted} CORRUPTED[/], [yellow]{missing} MISSING[/]";
            AnsiConsole.MarkupLine($"Summary: {summary}");
            return missing > 0 || corrupted > 0 ? 1 : 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(password);
            }
        });
    }

    private static string FormatSize(int bytes)
    {
        if (bytes >= 1024 * 1024) return $"{bytes / (1024 * 1024)} MB";
        if (bytes >= 1024) return $"{bytes / 1024} KB";
        return $"{bytes} B";
    }
}
