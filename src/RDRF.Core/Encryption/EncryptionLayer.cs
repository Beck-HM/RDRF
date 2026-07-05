using RDRF.Core.Dssa;
using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;

namespace RDRF.Core.Encryption;

/// <summary>
/// Static encryption layer providing all cryptographic operations:
/// key derivation, AES-CTR encrypt/decrypt, index/fragment encryption,
/// and auto-format detection.
///
/// Why CTR over GCM:
///   RDRF originally used AES-GCM for fragment and index encryption.
///   AES-GCM provides authenticated encryption with a 16-byte integrity
///   tag — any corruption makes decryption fail before the caller can
///   inspect the data.
///
///   This conflicts with the ETN (Erasure-Tolerant Node) architecture.
///   ETN requires bit-level read access to ALL data (Index, fragments, RC)
///   to perform cross-validation: it compares block-level hashes across
///   the three node types and repairs corrupted blocks from the healthy
///   nodes. If encryption produces an authentication tag, the data is
///   atomic — a single bit flip causes tag mismatch → decryption throws
///   → ETN never gets to inspect the blocks → repair is impossible.
///
///   Switching to AES-CTR (no authentication tag) resolves this:
///   ETN reads the raw decrypted data (CTR decrypt is bit-independent),
///   checks block-level integrity via its own hash comparison across
///   Index ↔ Fragment ↔ RC, and repairs corruption at the 64-byte block
///   level. ETN itself IS the integrity layer; GCM's auth tag was
///   redundant and counterproductive.
///
///   This decision is documented in commits:
///     83119a3 — switch RC/index encryption from AES-GCM to AES-CTR
///              for ETN compatibility
///     3021822 — CTR-only + ETN sole integrity: remove GCM fragment path
///              + HMAC
///
/// Key derivation:
///   Legacy: SHA256(rcCode) — single hash, no salt.
///   New: PBKDF2(rcCode, salt, 600k iterations, SHA256) — per-backup salt
///   stored in the first 32 bytes of the index file.
///
/// Format detection:
///   DecryptIndexWithAutoDetect tries the salt-prefixed format first
///   (data.Length ≥ 45 bytes). If the decrypted CBOR is valid, it returns.
///   Otherwise it falls back to the legacy SHA256-keyed format.
///   "Valid" means the CBOR map contains at least one known key
///   (file_fingerprint, version, or original_name).
///
/// All fragment/index methods use AES-CTR with caller-provided nonces or
/// auto-generated ones. Nonces are prepended to ciphertext (12 bytes).
/// </summary>
public static class EncryptionLayer
{
    private const int Pbkdf2Iterations = 600_000;
    // 32 (salt) + 12 (nonce) + 1 (minimum CBOR payload) = 45
    private const int MinNewFormatSize = Constants.SaltPrefixLength + Constants.NonceLength + 1;

    /// <summary>Derives a 32-byte AES key from rcCode + salt via PBKDF2 (600k iterations, SHA256).</summary>
    public static byte[] DeriveKey(byte[] rcCode, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(rcCode, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    /// <summary>Derives a 32-byte AES key from rcCode via SHA256 (legacy, no salt).</summary>
    public static byte[] DeriveKeyLegacy(byte[] rcCode)
        => SHA256.HashData(rcCode);

    /// <summary>Generates a cryptographically random rcCode (default 64 bytes).</summary>
    public static byte[] GenerateRcCode(int length = 64)
        => RandomNumberGenerator.GetBytes(length);

    /// <summary>Encrypts plaintext with AES-CTR using an auto-generated nonce (prepended).</summary>
    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey)
        => EncryptFragmentCtrWithKey(plaintext, aesKey);

    /// <summary>Encrypts with a caller-provided nonce. Output = nonce || ciphertext.</summary>
    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
    {
        byte[] ciphertext = CtrCryptWithKey(plaintext, aesKey, nonce);
        byte[] result = new byte[Constants.NonceLength + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        return result;
    }

    /// <summary>Decrypts fragment format: auto-generated nonce (prepended at offset 0).</summary>
    public static byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey)
        => DecryptFragmentCtrWithKey(encryptedData, aesKey);

    /// <summary>Decrypts fragment format with explicit offset (skips header bytes).</summary>
    public static byte[] DecryptFragmentWithKey(byte[] encryptedData, int offset, byte[] aesKey)
    {
        int nonceLen = Constants.NonceLength;
        int ciphertextLen = encryptedData.Length - offset - nonceLen;
        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted data length.");

        byte[] nonce = new byte[nonceLen];
        byte[] ciphertext = new byte[ciphertextLen];
        Buffer.BlockCopy(encryptedData, offset, nonce, 0, nonceLen);
        Buffer.BlockCopy(encryptedData, offset + nonceLen, ciphertext, 0, ciphertextLen);

        return AesNiCtr.CtrCrypt(ciphertext, aesKey, nonce);
    }

    private static byte[] CtrCryptWithKey(byte[] data, byte[] aesKey, byte[] nonce)
        => AesNiCtr.CtrCrypt(data, aesKey, nonce);

    private static byte[] CtrCrypt(byte[] data, byte[] rcCode, byte[] nonce)
        => CtrCryptWithKey(data, DeriveKeyLegacy(rcCode), nonce);

    /// <summary>Streaming AES-CTR transform. Reads input, writes decrypted output.</summary>
    public static void CtrTransformStream(Stream input, Stream output, byte[] aesKey, byte[] nonce)
    {
        AesNiCtr.CtrCryptStream(input, output, aesKey, nonce);
    }

    /// <summary>Encrypts plaintext with auto-generated nonce (CTR mode, no auth tag).</summary>
    public static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(Constants.NonceLength);
        return EncryptFragmentCtrWithKey(plaintext, aesKey, nonce);
    }

    /// <summary>Encrypts plaintext with caller-provided nonce.</summary>
    public static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
    {
        byte[] ciphertext = CtrCryptWithKey(plaintext, aesKey, nonce);
        byte[] result = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        return result;
    }

    /// <summary>Encrypts with rcCode-derived legacy key (SHA256).</summary>
    public static byte[] EncryptFragmentCtr(byte[] plaintext, byte[] rcCode)
        => EncryptFragmentCtrWithKey(plaintext, DeriveKeyLegacy(rcCode));

    /// <summary>Decrypts CTR-mode fragment. Expects nonce prepended at offset 0.</summary>
    public static byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey)
        => DecryptFragmentCtrWithKey(encryptedData, 0, aesKey);

    /// <summary>Decrypts CTR-mode fragment with explicit offset.</summary>
    public static byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, int offset, byte[] aesKey)
    {
        int nonceLen = Constants.NonceLength;
        int ciphertextLen = encryptedData.Length - offset - nonceLen;
        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted data length.");

        byte[] nonce = new byte[nonceLen];
        byte[] ciphertext = new byte[ciphertextLen];
        Buffer.BlockCopy(encryptedData, offset, nonce, 0, nonceLen);
        Buffer.BlockCopy(encryptedData, offset + nonceLen, ciphertext, 0, ciphertextLen);

        return AesNiCtr.CtrCrypt(ciphertext, aesKey, nonce);
    }

    /// <summary>Legacy decrypt with SHA256-derived key.</summary>
    public static byte[] DecryptFragmentCtr(byte[] encryptedData, byte[] rcCode)
        => DecryptFragmentCtrWithKey(encryptedData, DeriveKeyLegacy(rcCode));

    /// <summary>
    /// Decrypt a fragment and strip its embedded index header.
    /// Handles both headerless (old format) and 0xFF01-header formats.
    /// Returns the raw fragment payload for FSS decoding or integrity checks.
    /// </summary>
    public static byte[] DecryptAndStripFragment(byte[] encryptedData, byte[] aesKey)
    {
        bool hasHeader = FragmentFileHeader.HasHeader(encryptedData);
        int hdrOff = hasHeader ? FragmentFileHeader.GetTotalHeaderSize(encryptedData) : 0;
        int nonceLen = Constants.NonceLength;
        int ciphertextLen = encryptedData.Length - hdrOff - nonceLen;
        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted data length.");

        byte[] nonce = new byte[nonceLen];
        Buffer.BlockCopy(encryptedData, hdrOff, nonce, 0, nonceLen);

        byte[] ciphertext = ArrayPool<byte>.Shared.Rent(ciphertextLen);
        byte[] output = ArrayPool<byte>.Shared.Rent(ciphertextLen);
        try
        {
            Buffer.BlockCopy(encryptedData, hdrOff + nonceLen, ciphertext, 0, ciphertextLen);
            AesNiCtr.CtrCrypt(ciphertext.AsSpan(0, ciphertextLen), output.AsSpan(0, ciphertextLen), aesKey, nonce);

            if (hasHeader && ciphertextLen >= 4)
            {
                int idxLen = BitConverter.ToInt32(output.AsSpan(0, 4));
                if (idxLen > 0 && idxLen <= ciphertextLen - 4)
                {
                    int dataLen = ciphertextLen - (4 + idxLen);
                    byte[] result = new byte[dataLen];
                    Buffer.BlockCopy(output, 4 + idxLen, result, 0, dataLen);
                    CryptographicOperations.ZeroMemory(output.AsSpan(0, 4 + idxLen));
                    return result;
                }
            }

            byte[] clean = new byte[ciphertextLen];
            Buffer.BlockCopy(output, 0, clean, 0, ciphertextLen);
            return clean;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ciphertext, clearArray: true);
            ArrayPool<byte>.Shared.Return(output, clearArray: true);
        }
    }

    /// <summary>Encrypts index data with AES-CTR (no salt prefix).</summary>
    public static byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey)
        => EncryptFragmentWithKey(indexData, aesKey);

    /// <summary>Encrypts index with legacy rcCode-derived key.</summary>
    public static byte[] EncryptIndex(byte[] indexData, byte[] rcCode)
        => EncryptIndexWithKey(indexData, DeriveKeyLegacy(rcCode));

    /// <summary>Decrypts index encrypted with EncryptIndexWithKey.</summary>
    public static byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey)
        => DecryptFragmentWithKey(encryptedIndex, aesKey);

    /// <summary>Decrypts index encrypted with legacy SHA256 key derivation.</summary>
    public static byte[] DecryptIndex(byte[] encryptedIndex, byte[] rcCode)
        => DecryptIndexWithKey(encryptedIndex, DeriveKeyLegacy(rcCode));

    // ── Salt-prefixed index format (new) ──

    /// <summary>
    /// Encrypts index data with PBKDF2-derived key. Output:
    ///   [32-byte salt] [nonce] [ciphertext]
    /// The salt is randomly generated and returned via out parameter.
    /// </summary>
    public static byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password, out byte[] salt)
    {
        salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        byte[] aesKey = DeriveKey(password, salt);
        byte[] encrypted = EncryptIndexWithKey(indexData, aesKey);

        byte[] result = new byte[Constants.SaltPrefixLength + encrypted.Length];
        Buffer.BlockCopy(salt, 0, result, 0, Constants.SaltPrefixLength);
        Buffer.BlockCopy(encrypted, 0, result, Constants.SaltPrefixLength, encrypted.Length);
        return result;
    }

    /// <summary>Encrypts index with PBKDF2-derived key (discards salt).</summary>
    public static byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password)
        => EncryptIndexWithSaltPrefix(indexData, password, out _);

    /// <summary>
    /// Encrypts index with PBKDF2-derived key using an existing salt
    /// (for incremental backups where the salt must stay the same).
    /// </summary>
    public static byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password, byte[]? existingSalt)
    {
        byte[] salt = (existingSalt != null && existingSalt.Length == Constants.SaltPrefixLength)
            ? existingSalt
            : RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        byte[] aesKey = DeriveKey(password, salt);
        byte[] encrypted = EncryptIndexWithKey(indexData, aesKey);

        byte[] result = new byte[Constants.SaltPrefixLength + encrypted.Length];
        Buffer.BlockCopy(salt, 0, result, 0, Constants.SaltPrefixLength);
        Buffer.BlockCopy(encrypted, 0, result, Constants.SaltPrefixLength, encrypted.Length);
        return result;
    }

    /// <summary>
    /// Decrypts index with auto-format detection. Tries salt-prefixed format
    /// first (data.Length ≥ 45). If the decrypted CBOR is valid (contains at
    /// least one expected key), returns that result. Falls back to legacy
    /// SHA256-keyed format.
    ///
    /// Throws CryptographicException if neither format succeeds.
    /// </summary>
    public static (byte[] aesKey, byte[] indexCbor) DecryptIndexWithAutoDetect(byte[] data, byte[] password)
    {
        if (data.Length >= MinNewFormatSize)
        {
            byte[] salt = new byte[Constants.SaltPrefixLength];
            Buffer.BlockCopy(data, 0, salt, 0, Constants.SaltPrefixLength);

            byte[] encrypted = new byte[data.Length - Constants.SaltPrefixLength];
            Buffer.BlockCopy(data, Constants.SaltPrefixLength, encrypted, 0, encrypted.Length);

            byte[] aesKey = DeriveKey(password, salt);
            byte[] cbor = DecryptIndexWithKey(encrypted, aesKey);
            if (IsValidCbor(cbor))
                return (aesKey, cbor);
        }

        byte[] legacyKey = DeriveKeyLegacy(password);
        byte[] legacyCbor = DecryptIndexWithKey(data, legacyKey);
        if (IsValidCbor(legacyCbor))
            return (legacyKey, legacyCbor);

        throw new CryptographicException("Wrong password or corrupt index file");
    }

    /// <summary>
    /// Validates that a CBOR byte array is a valid RDRF index by checking
    /// for at least one expected map key (file_fingerprint, version, or
    /// original_name).
    /// </summary>
    private static bool IsValidCbor(byte[] data)
    {
        try
        {
            var reader = new CborReader(data);
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                string key = reader.ReadTextString();
                if (key is "file_fingerprint" or "version" or "original_name")
                    return true;
                reader.SkipValue();
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
}
