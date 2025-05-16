using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using RDRF.Core.Encryption;
using RDRF.Core.Integrity;
using RDRF.Cli.Services;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class StatusCommand : Command
{
    public StatusCommand() : base("status", "Show fragment status for a backup")
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

            string storageDir = indexFile.DirectoryName!;
            var storage = new LocalFileAdapter(storageDir);
            byte[] aesKey = EncryptionLayer.DeriveKey(password);
            string prefix = index.CustomName ?? index.FileFingerprint;
            string lookupKey = index.CustomName ?? index.FileFingerprint;

            // Check index and RC presence
            bool indexOk = true;
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

            bool hasEtn = index.Fss6FragentBlockMaps != null || index.Fss6RcBlockMap != null;

            Console.WriteLine();
            Console.WriteLine($"Fingerprint:  {index.FileFingerprint}");
            Console.WriteLine($"File:         {index.OriginalName}");
            Console.WriteLine($"Strategy:     {index.FssStrategy}{(hasEtn ? " + FSS6" : "")}");
            Console.WriteLine();
            Console.WriteLine("Backup Infrastructure:");
            Console.WriteLine($"  Index:       {(indexOk ? "OK" : "MISSING")}");
            Console.WriteLine($"  RC:          {(rcOk ? "OK" : (storage.RcExists(lookupKey) ? "CORRUPTED" : "MISSING"))}");
            Console.WriteLine();

            // Scan fragments
            int ok = 0, corrupted = 0, missing = 0;
            var rows = new List<(int idx, string status, string size, string hash)>();

            for (int i = 0; i < index.FragentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragentFilename(prefix, i);
                if (!storage.FragmentExists(fname))
                {
                    rows.Add((i, "MISSING", "-", "-"));
                    missing++;
                    continue;
                }

                try
                {
                    byte[] encrypted = storage.ReadFragment(fname);
                    bool hasHeader = FragmentFileHeader.HasHeader(encrypted);
                    int hdrOff = hasHeader ? 6 : 0;
                    byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrOff, aesKey);

                    if (hasHeader && decrypted.Length >= 4)
                    {
                        int idxLen = BitConverter.ToInt32(decrypted.AsSpan(0, 4));
                        if (idxLen > 4 && idxLen <= decrypted.Length - 4)
                            decrypted = decrypted[(4 + idxLen)..];
                    }

                    if (hasEtn)
                    {
                        var (rawData, _, _, _, _, _, _) = RDRF.Core.ETN.EtnTrailer.Parse(decrypted);
                        decrypted = rawData;
                    }

                    string actualHash = IntegrityChecker.HashBytes(decrypted);
                    string expectedHash = index.FragentHashes.Count > i ? index.FragentHashes[i] : "";
                    bool match = IntegrityChecker.VerifyHash(actualHash, expectedHash);

                    string sizeStr = index.OriginalFragentSizes.Count > i
                        ? FormatSize(index.OriginalFragentSizes[i]) : FormatSize(decrypted.Length);

                    if (match)
                    {
                        rows.Add((i, "OK", sizeStr, "\u2705"));
                        ok++;
                    }
                    else
                    {
                        rows.Add((i, "CORRUPTED", sizeStr, "\u274C"));
                        corrupted++;
                    }
                }
                catch
                {
                    rows.Add((i, "CORRUPTED", "-", "-"));
                    corrupted++;
                }
            }

            // Print table
            Console.WriteLine($"Fragment Status ({index.FragentCount} expected):");
            Console.WriteLine($"  #  Status      Size       Hash");
            Console.WriteLine($" -- ---------- ---------- ----------");
            foreach (var r in rows)
                Console.WriteLine($"  {r.idx,-2} {r.status,-10} {r.size,-10} {r.hash}");

            Console.WriteLine();
            Console.WriteLine($"Summary: {ok}/{index.FragentCount} OK, {corrupted} CORRUPTED, {missing} MISSING");
            return missing > 0 || corrupted > 0 ? 1 : 0;
        });
    }

    private static string FormatSize(int bytes)
    {
        if (bytes >= 1024 * 1024) return $"{bytes / (1024 * 1024)} MB";
        if (bytes >= 1024) return $"{bytes / 1024} KB";
        return $"{bytes} B";
    }
}
