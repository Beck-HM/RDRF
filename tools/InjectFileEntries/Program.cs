using System.Formats.Cbor;
using RDRF.Core.Encryption;
using RDRF.Core.Index;

string indexFile = args[0];
byte[] password = System.Text.Encoding.UTF8.GetBytes(args[1]);

byte[] encrypted = File.ReadAllBytes(indexFile);
(byte[] aesKey, byte[] cbor) = EncryptionLayer.DecryptIndexWithAutoDetect(encrypted, password);
var index = IndexManager.DeserializeIndex(cbor);

if (index.Versions == null || index.Versions.Count == 0)
{
    Console.Error.WriteLine("No versions found");
    return 1;
}

// Inject multi-file entries into v2 and v3
for (int vi = 0; vi < index.Versions.Count; vi++)
{
    var v = index.Versions[vi];
    if (v.Version == 1) continue; // skip initial

    v.Files = new List<RDRF.Core.Versioning.FileEntry>
    {
        new() { Path = "src/calc.py", ChangeType = "modified", Diff = v.SystemDiff },
        new() { Path = "src/utils/helpers.py", ChangeType = v.Version == 2 ? "added" : "modified",
                Diff = v.Version == 2 ? "+def mul(a, b):\n+    return a * b\n" : "+def div(a, b):\n+    return a / b\n" },
        new() { Path = "tests/test_calc.py", ChangeType = "added",
                Diff = "+def test_add():\n+    assert add(1,2) == 3\n+def test_sub():\n+    assert sub(5,3) == 2\n" },
    };
}

byte[] newCbor = IndexManager.SerializeIndex(index);

// Re-encrypt with same salt (first 32 bytes of original encrypted file)
byte[] salt = new byte[32];
Buffer.BlockCopy(encrypted, 0, salt, 0, 32);
byte[] saltedIndex = EncryptionLayer.EncryptIndexWithSaltPrefix(newCbor, password, salt);
File.WriteAllBytes(indexFile, saltedIndex);

Console.WriteLine($"Injected {index.Versions.Count - 1} version(s) with multi-file entries");
return 0;
