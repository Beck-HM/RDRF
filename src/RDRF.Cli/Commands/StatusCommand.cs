using System.Text.Json;
using RDRF.Core;
using RDRF.Core.Compression.Ckc;
using RDRF.Core.Index;
using RDRF.Core.DSAA;
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
        var jsonOpt = new Option<bool>("--json") { Description = "Output as JSON" };

        Arguments.Add(indexArg);
        Options.Add(passwordOpt);
        Options.Add(jsonOpt);

        SetAction(async (ParseResult parseResult) =>
        {
            var indexFile = parseResult.GetValue(indexArg);
            var pwd = parseResult.GetValue(passwordOpt);
            bool json = parseResult.GetValue(jsonOpt);

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
                    if (json) { Console.WriteLine(JsonSerializer.Serialize(new { error = "Wrong password or corrupted index file" })); }
                    else { AnsiConsole.MarkupLine("[red]Error: wrong password or corrupted index file[/]"); }
                    return 1;
                }

                string storageDir = indexFile.DirectoryName!;
                var storage = new LocalDSAAAdapter(storageDir);
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

                bool hasEtn = index.HasFss6EtnData;

                bool isCkc = string.Equals(index.Compression, "ckc", StringComparison.OrdinalIgnoreCase);
                var ckcAlgo = isCkc ? new CkcAlgorithm() : null;

                int ok = 0, corrupted = 0, missing = 0;
                var rows = new List<(int idx, string status, string size, string hash, int rawSize)>();

                for (int i = 0; i < index.FragmentCount; i++)
                {
                    string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                    if (!storage.FragmentExists(fname))
                    {
                        rows.Add((i, "MISSING", "-", "-", 0));
                        missing++;
                        continue;
                    }

                    try
                    {
                        byte[] encrypted = storage.ReadFragment(fname);
                        // Payload after decrypt: [compressed?] body [+ FSS6 trailers].
                        // fragment_hashes are post-FSS-encode, pre-compress, pre-trailer.
                        byte[] body = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);

                        // Trailers outer → inner (same as restore StripAnyTrailer)
                        var (raw62, _, _, _, _) = RDRF.Core.FSS.Fss62RepairTrailer.Parse(body);
                        body = raw62;
                        var (raw61, _, _, _, _) = RDRF.Core.FSS.Fss61RepairTrailer.Parse(body);
                        body = raw61;
                        body = RDRF.Core.ETN.EtnTrailer.Parse(body).RawData;

                        // Decompress after trailer strip (matches backup: compress then trailers for 6.x off; or compress after ETN for pure FSS6)
                        if (!string.IsNullOrEmpty(index.Compression))
                        {
                            if (isCkc && ckcAlgo!.CanHandle(body))
                                body = ckcAlgo.Decompress(body);
                            else if (!isCkc)
                                body = RDRF.Core.Compression.Compressor.Decompress(body, index.Compression);
                        }

                        string actualHash = IntegrityChecker.HashBytes(body);
                        string expectedHash = index.FragmentHashes.Count > i ? index.FragmentHashes[i] : "";
                        bool match = IntegrityChecker.VerifyHash(actualHash, expectedHash);
                        int fragSize = index.OriginalFragmentSizes.Count > i ? index.OriginalFragmentSizes[i] : body.Length;
                        string sizeStr = FormatSize(fragSize);

                        if (match)
                        {
                            rows.Add((i, "OK", sizeStr, "\u2705", fragSize));
                            ok++;
                        }
                        else
                        {
                            rows.Add((i, "CORRUPTED", sizeStr, "\u274C", fragSize));
                            corrupted++;
                        }
                    }
                    catch
                    {
                        rows.Add((i, "CORRUPTED", "-", "\u274C", 0));
                        corrupted++;
                    }
                }

                if (json)
                {
                    var fragments = rows.Select(r => new
                    {
                        index = r.idx,
                        status = r.status,
                        size = r.rawSize > 0 ? r.rawSize : (int?)null,
                        hashMatch = r.hash switch { "\u2705" => true, "\u274C" => false, _ => (bool?)null }
                    }).ToList();
                    var result = new
                    {
                        fingerprint = index.FileFingerprint,
                        originalName = index.OriginalName,
                        fileSize = index.FileSize,
                        fssStrategy = index.FssStrategy + (hasEtn ? " + FSS6" : ""),
                        compression = index.Compression,
                        hasEtn,
                        indexOk,
                        rcOk,
                        fragments,
                        summary = new { total = index.FragmentCount, ok, corrupted, missing }
                    };
                    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
                    return missing > 0 || corrupted > 0 ? 1 : 0;
                }

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

                var fragmentTable = new Table();
                fragmentTable.Border(TableBorder.Rounded);
                fragmentTable.AddColumn(new TableColumn("#").RightAligned());
                fragmentTable.AddColumn("Status");
                fragmentTable.AddColumn("Size");
                fragmentTable.AddColumn("Hash");
                foreach (var r in rows)
                {
                    string displayStatus = r.status switch
                    {
                        "OK" => "[green]OK[/]",
                        "MISSING" => "[yellow]MISSING[/]",
                        "CORRUPTED" => "[red]CORRUPTED[/]",
                        "ENCRYPTED (ETN)" => "[yellow]ENCRYPTED (ETN)[/]",
                        _ => r.status
                    };
                    fragmentTable.AddRow(r.idx.ToString(), displayStatus, r.size, r.hash);
                }
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







