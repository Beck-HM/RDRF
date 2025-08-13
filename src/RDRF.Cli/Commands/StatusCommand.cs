using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using RDRF.Core.Encryption;
using RDRF.Core.Integrity;
using RDRF.Cli.Services;
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
                Console.Error.WriteLine($"Error: index file not found: {indexFile.FullName}");
                return 1;
            }

            byte[] password = pwd != null ? Encoding.UTF8.GetBytes(pwd) : PasswordProvider.ReadInteractive();
            try
            {
                if (password.Length == 0)
                {
                    Console.Error.WriteLine("Error: password cannot be empty");
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
                    Console.Error.WriteLine("Error: wrong password or corrupted index file");
                    return 1;
                }

                string storageDir = indexFile.DirectoryName!;
                var storage = new LocalFileAdapter(storageDir);
                string prefix = index.CustomName ?? index.FileFingerprint;
                string lookupKey = index.CustomName ?? index.FileFingerprint;

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

            bool hasEtn = index.Fss6FragmentBlockMaps != null || index.Fss6RcBlockMap != null;

            Console.WriteLine();
            Console.WriteLine($"Fingerprint:  {index.FileFingerprint}");
            Console.WriteLine($"File:         {index.OriginalName}");
            Console.WriteLine($"Strategy:     {index.FssStrategy}{(hasEtn ? " + FSS6" : "")}");
            Console.WriteLine();
            Console.WriteLine("Backup Infrastructure:");
            Console.WriteLine($"  Index:       {(indexOk ? "OK" : "MISSING")}");
            Console.WriteLine($"  RC:          {(rcOk ? "OK" : (storage.RcExists(lookupKey) ? "CORRUPTED" : "MISSING"))}");
            Console.WriteLine();

            int ok = 0, corrupted = 0, missing = 0;
            var rows = new List<(int idx, string status, string size, string hash)>();

            for (int i = 0; i < index.FragmentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragmentFilename(prefix, i);
                if (!storage.FragmentExists(fname))
                {
                    rows.Add((i, "MISSING", "-", "-"));
                    missing++;
                    continue;
                }

                try
                {
                    byte[] encrypted = storage.ReadFragment(fname);
                    byte[] decrypted = EncryptionLayer.DecryptAndStripFragment(encrypted, aesKey);

                    if (hasEtn)
                    {
                        var (rawData, _, _, _, _, _, _) = RDRF.Core.ETN.EtnTrailer.Parse(decrypted);
                        decrypted = rawData;
                    }

                    string actualHash = IntegrityChecker.HashBytes(decrypted);
                    string expectedHash = index.FragmentHashes.Count > i ? index.FragmentHashes[i] : "";
                    bool match = IntegrityChecker.VerifyHash(actualHash, expectedHash);

                    string sizeStr = index.OriginalFragmentSizes.Count > i
                        ? FormatSize(index.OriginalFragmentSizes[i]) : FormatSize(decrypted.Length);

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

            Console.WriteLine($"Fragment Status ({index.FragmentCount} expected):");
            Console.WriteLine($"  #  Status      Size       Hash");
            Console.WriteLine($" -- ---------- ---------- ----------");
            foreach (var r in rows)
                Console.WriteLine($"  {r.idx,-2} {r.status,-10} {r.size,-10} {r.hash}");

            Console.WriteLine();
            Console.WriteLine($"Summary: {ok}/{index.FragmentCount} OK, {corrupted} CORRUPTED, {missing} MISSING");
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
