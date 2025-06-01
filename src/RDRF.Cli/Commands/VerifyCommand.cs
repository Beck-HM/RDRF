using RDRF.Core;
using RDRF.Core.Index;
using RDRF.Core.Storage;
using RDRF.Core.Encryption;
using RDRF.Core.FSS;
using RDRF.Cli.Services;
using System.CommandLine;
using System.Text;

namespace RDRF.Cli.Commands;

public class VerifyCommand : Command
{
    public VerifyCommand() : base("verify", "Run ETN cross-validation on FSS6 backup via index file")
    {
        var indexArg = new Argument<FileInfo>("indexFile") { Description = "Path to the .indrdrf index file" };
        var passwordOpt = new Option<string?>("-password") { Description = "Password as plain text (omit for interactive prompt)" };

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
            if (password.Length == 0)
            {
                Console.Error.WriteLine("Error: password cannot be empty");
                return 1;
            }
            byte[] encryptedIndex = File.ReadAllBytes(indexFile.FullName);

            RdrfIndex index;
            byte[] aesKey;
            try
            {
                (aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, password);
                index = RDRFEngine.DeserializeIndex(cbor);
            }
            catch
            {
                Console.Error.WriteLine("Error: wrong password or corrupted index file");
                return 1;
            }

            if (index.Fss6FragentBlockMaps == null && index.Fss6RcBlockMap == null)
            {
                Console.Error.WriteLine("Error: backup does not contain FSS6/ETN data — verification requires FSS6");
                return 1;
            }

            string storageDir = indexFile.DirectoryName!;
            var storage = new LocalFileAdapter(storageDir);
            string prefix = index.CustomName ?? index.FileFingerprint;

            // Read and decrypt RC file
            byte[] encryptedRc = storage.ReadRc(prefix);
            byte[] rcBytes = EncryptionLayer.DecryptFragmentWithKey(encryptedRc, aesKey);

            // Read and decrypt all fragments
            var fragments = new List<byte[]>();
            for (int i = 0; i < index.FragentCount; i++)
            {
                string fname = RDRF.Core.FragmentEngine.Frags.FragentFilename(prefix, i);
                if (!storage.FragmentExists(fname)) continue;

                byte[] encrypted = storage.ReadFragment(fname);
                bool hasHeader = FragmentFileHeader.HasHeader(encrypted);
                int hdrOff = hasHeader ? FragmentFileHeader.GetTotalHeaderSize(encrypted) : 0;
                byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(encrypted, hdrOff, aesKey);

                if (hasHeader && decrypted.Length >= 4)
                {
                    int idxLen = BitConverter.ToInt32(decrypted.AsSpan(0, 4));
                    if (idxLen > 4 && idxLen <= decrypted.Length - 4)
                        decrypted = decrypted[(4 + idxLen)..];
                }

                fragments.Add(decrypted);
            }

            byte[] indexBytes = IndexManager.SerializeIndex(index);
            var result = Fss6Etn.CrossValidate(indexBytes, fragments, rcBytes);

            // Print results
            Console.WriteLine($"Fingerprint: {index.FileFingerprint}");
            Console.WriteLine($"Strategy:    {index.FssStrategy} + FSS6");
            Console.WriteLine($"Fragments:   {fragments.Count}/{index.FragentCount} available");

            if (result.IsValid)
            {
                Console.WriteLine($"Status: VALID");
                return 0;
            }

            Console.WriteLine($"Status: CORRUPTED");

            if (result.IndexCorrupted)
            {
                string blocks = FormatBlockList(result.IndexCorruptedBlocks);
                Console.WriteLine($"Index:  CORRUPTED ({result.IndexCorruptedBlocks.Count} blocks{blocks})");
            }
            else
                Console.WriteLine($"Index:  OK");

            if (result.RcCorrupted)
            {
                string blocks = FormatBlockList(result.RcCorruptedBlocks);
                Console.WriteLine($"RC:     CORRUPTED ({result.RcCorruptedBlocks.Count} blocks{blocks})");
            }
            else
                Console.WriteLine($"RC:     OK");

            if (result.CorruptedFragments.Count > 0)
            {
                Console.WriteLine($"Fragments corrupted: {result.CorruptedFragments.Count}/{fragments.Count}");
                foreach (int fi in result.CorruptedFragments.OrderBy(x => x))
                {
                    var blocks = result.CorruptedFragmentBlocks.ContainsKey(fi)
                        ? result.CorruptedFragmentBlocks[fi]
                        : new List<int>();
                    Console.WriteLine($"  Fragment {fi}: {blocks.Count} blocks {FormatBlockList(blocks)}");
                }
            }
            else
                Console.WriteLine($"Fragments: OK");

            if (result.CorruptedFragmentTrailers.Count > 0)
            {
                string trailers = string.Join(",", result.CorruptedFragmentTrailers.OrderBy(x => x));
                Console.WriteLine($"Trailers corrupted: fragments [{trailers}]");
            }

            int suspicious = result.SuspiciousFragmentBlocks?.Values.Sum(v => v.Count) ?? 0;
            if (suspicious > 0)
                Console.WriteLine($"Suspicious (false positives): {suspicious}");

            return 1;
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
