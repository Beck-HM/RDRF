using RDRF.Core.DSAA;
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
///   tag - any corruption makes decryption fail before the caller can
///   inspect the data.
///
///   This conflicts with the ETN (Erasure-Tolerant Node) architecture.
///   ETN requires bit-level read access to ALL data (Index, fragments, RC)
///   to perform cross-validation: it compares block-level hashes across
///   the three node types and repairs corrupted blocks from the healthy
///   nodes. If encryption produces an authentication tag, the data is
///   atomic - a single bit flip causes tag mismatch -> decryption throws
///   -> ETN never gets to inspect the blocks -> repair is impossible.
///
///   Switching to AES-CTR (no authentication tag) resolves this:
///   ETN reads the raw decrypted data (CTR decrypt is bit-independent),
///   checks block-level integrity via its own hash comparison across
///   Index <-> Fragment <-> RC, and repairs corruption at the 64-byte block
///   level. ETN itself IS the integrity layer; GCM's auth tag was
///   redundant and counterproductive.
///
///   This decision is documented in commits:
///     83119a3 - switch RC/index encryption from AES-GCM to AES-CTR
///              for ETN compatibility
///     3021822 - CTR-only + ETN sole integrity: remove GCM fragment path
///              + HMAC
///
/// Key derivation:
///   Legacy: SHA256(rcCode) - single hash, no salt.
///   New: PBKDF2(rcCode, salt, 600k iterations, SHA256) - per-backup salt
///   stored in the first 32 bytes of the index file.
///
/// Format detection:
///   DecryptIndexWithAutoDetect tries the salt-prefixed format first
///   (data.Length >= 45 bytes). If the decrypted CBOR is valid, it returns.
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
    {
        if (plaintext.Length > Constants.MaxSingleEncryptSize)
            throw new ArgumentException($"Encrypt size {plaintext.Length} exceeds per-call limit of {Constants.MaxSingleEncryptSize}");
        return EncryptFragmentCtrWithKey(plaintext, aesKey);
    }

    /// <summary>Encrypts with a caller-provided nonce. Output = nonce || ciphertext.</summary>
    private static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
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

    /// <summary>Encrypts plaintext with caller-provided nonce (single output alloc: nonce||ct).</summary>
    private static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
        => EncryptFragmentCtrWithKey(plaintext.AsSpan(), aesKey, nonce);

    /// <summary>Span overload: one allocation for nonce||ciphertext, in-place CTR into the ct region.</summary>
    internal static byte[] EncryptFragmentCtrWithKey(ReadOnlySpan<byte> plaintext, byte[] aesKey, byte[]? nonce = null)
    {
        nonce ??= RandomNumberGenerator.GetBytes(Constants.NonceLength);
        byte[] result = new byte[nonce.Length + plaintext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        plaintext.CopyTo(result.AsSpan(nonce.Length));
        AesNiCtr.CtrCrypt(result.AsSpan(nonce.Length), result.AsSpan(nonce.Length), aesKey, nonce);
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

    /// <summary>
    /// Stream-decrypt a fragment file and strip the embedded index header.
    /// Does not load the full ciphertext into a separate managed buffer (file stream → single plain buffer).
    /// Prefer this over ReadAllBytes + <see cref="DecryptAndStripFragment"/> on large fragments.
    /// </summary>
    public static byte[] DecryptAndStripFragmentFromStream(Stream input, byte[] aesKey)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!input.CanRead)
            throw new ArgumentException("Stream must be readable.", nameof(input));

        long startPos = input.CanSeek ? input.Position : 0;
        long available = input.CanSeek ? input.Length - startPos : -1;

        // Probe header (magic + version + optional salt length).
        Span<byte> probe = stackalloc byte[FragmentFileHeader.HeaderSize];
        ReadExact(input, probe);
        bool hasHeader = probe[0] == 0xFF && probe[1] == 0x01;
        int hdrOff = 0;
        if (hasHeader)
        {
            int saltLen = 0;
            if (probe[2] >= 2 && probe.Length >= 4)
                saltLen = probe[3];
            hdrOff = FragmentFileHeader.HeaderSize + saltLen;
            // Consume remaining header bytes after the 6-byte probe.
            int already = FragmentFileHeader.HeaderSize;
            if (hdrOff > already)
            {
                Span<byte> rest = stackalloc byte[hdrOff - already];
                ReadExact(input, rest);
            }
        }
        else
        {
            // Not a headered fragment: rewind probe into ciphertext path.
            // Re-seek if possible; otherwise we already consumed 6 bytes that are part of nonce+ct.
            if (input.CanSeek)
            {
                input.Position = startPos;
                hdrOff = 0;
            }
            else
            {
                // Non-seekable without header: treat the 6 probe bytes as start of nonce||ct
                // by buffering them — rare for local restore (FileStream is seekable).
                return DecryptAndStripFragmentFromStreamNonSeekNoHeader(input, probe, aesKey);
            }
        }

        int nonceLen = Constants.NonceLength;
        byte[] nonce = new byte[nonceLen];
        ReadExact(input, nonce);

        int ciphertextLen;
        if (available >= 0)
        {
            ciphertextLen = checked((int)(available - hdrOff - nonceLen));
        }
        else
        {
            // Drain remaining into pool buffer (fallback).
            using var ms = new MemoryStream();
            input.CopyTo(ms);
            byte[] ct = ms.ToArray();
            return StripAfterDecrypt(AesNiCtr.CtrCrypt(ct, aesKey, nonce), hasHeader);
        }

        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted fragment length.");
        if (ciphertextLen == 0)
            return Array.Empty<byte>();

        // Single plain buffer: stream CTR decrypt file → plain (no full encrypted byte[]).
        byte[] plain = new byte[ciphertextLen];
        using (var plainMs = new MemoryStream(plain, 0, ciphertextLen, writable: true, publiclyVisible: true))
        {
            // Limit input to remaining ciphertext bytes.
            using var limited = new LimitedReadStream(input, ciphertextLen);
            AesNiCtr.CtrCryptStream(limited, plainMs, aesKey, nonce);
        }

        return StripAfterDecrypt(plain, hasHeader);
    }

    /// <summary>Async variant of <see cref="DecryptAndStripFragmentFromStream"/>.</summary>
    public static async Task<byte[]> DecryptAndStripFragmentFromStreamAsync(
        Stream input, byte[] aesKey, CancellationToken ct = default)
    {
        // Sync path is CPU-bound CTR over FileStream; offload only if caller needs true async I/O.
        // Prefer sync for local sequential FileStream (already efficient).
        ct.ThrowIfCancellationRequested();
        if (input is FileStream fs && fs.IsAsync)
        {
            // Read header/nonce async then CTR on buffer — keep parity with sync for correctness.
            return await Task.Run(() => DecryptAndStripFragmentFromStream(input, aesKey), ct).ConfigureAwait(false);
        }
        return DecryptAndStripFragmentFromStream(input, aesKey);
    }

    private static byte[] DecryptAndStripFragmentFromStreamNonSeekNoHeader(
        Stream input, ReadOnlySpan<byte> alreadyRead, byte[] aesKey)
    {
        using var ms = new MemoryStream();
        ms.Write(alreadyRead);
        input.CopyTo(ms);
        return DecryptAndStripFragment(ms.ToArray(), aesKey);
    }

    private static byte[] StripAfterDecrypt(byte[] plain, bool hasHeader)
    {
        if (hasHeader && plain.Length >= 4)
        {
            int idxLen = BitConverter.ToInt32(plain.AsSpan(0, 4));
            if (idxLen > 0 && idxLen <= plain.Length - 4)
            {
                int dataLen = plain.Length - (4 + idxLen);
                byte[] result = new byte[dataLen];
                Buffer.BlockCopy(plain, 4 + idxLen, result, 0, dataLen);
                CryptographicOperations.ZeroMemory(plain.AsSpan(0, 4 + idxLen));
                return result;
            }
        }
        return plain;
    }

    private static void ReadExact(Stream input, Span<byte> dest)
    {
        int offset = 0;
        while (offset < dest.Length)
        {
            int n = input.Read(dest.Slice(offset));
            if (n == 0)
                throw new EndOfStreamException("Unexpected end of fragment stream.");
            offset += n;
        }
    }

    /// <summary>Limits reads to a fixed number of bytes from an underlying stream.</summary>
    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        public LimitedReadStream(Stream inner, long remaining)
        {
            _inner = inner;
            _remaining = remaining;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0) return 0;
            int toRead = (int)Math.Min(count, _remaining);
            int n = _inner.Read(buffer, offset, toRead);
            _remaining -= n;
            return n;
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

    // -- Salt-prefixed index format (new) --

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
    /// first (data.Length >= 45). If the decrypted CBOR is valid (contains at
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
