using RDRF.Core.Dssa;
using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;

namespace RDRF.Core.Encryption;

public static class EncryptionLayer
{
    private const int Pbkdf2Iterations = 600_000;
    private const int MinNewFormatSize = Constants.SaltPrefixLength + Constants.NonceLength + 1;

    public static byte[] DeriveKey(byte[] rcCode, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(rcCode, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    public static byte[] DeriveKeyLegacy(byte[] rcCode)
        => SHA256.HashData(rcCode);

    public static byte[] GenerateRcCode(int length = 64)
        => RandomNumberGenerator.GetBytes(length);

    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey)
        => EncryptFragmentCtrWithKey(plaintext, aesKey);

    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
    {
        byte[] ciphertext = CtrCryptWithKey(plaintext, aesKey, nonce);
        byte[] result = new byte[Constants.NonceLength + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        return result;
    }

    public static byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey)
        => DecryptFragmentCtrWithKey(encryptedData, aesKey);

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
    {
        return AesNiCtr.CtrCrypt(data, aesKey, nonce);
    }

    private static byte[] CtrCrypt(byte[] data, byte[] rcCode, byte[] nonce)
        => CtrCryptWithKey(data, DeriveKeyLegacy(rcCode), nonce);

    public static void CtrTransformStream(Stream input, Stream output, byte[] aesKey, byte[] nonce)
    {
        AesNiCtr.CtrCryptStream(input, output, aesKey, nonce);
    }

    public static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(Constants.NonceLength);
        return EncryptFragmentCtrWithKey(plaintext, aesKey, nonce);
    }

    public static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce)
    {
        byte[] ciphertext = CtrCryptWithKey(plaintext, aesKey, nonce);
        byte[] result = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        return result;
    }

    public static byte[] EncryptFragmentCtr(byte[] plaintext, byte[] rcCode)
        => EncryptFragmentCtrWithKey(plaintext, DeriveKeyLegacy(rcCode));

    public static byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey)
        => DecryptFragmentCtrWithKey(encryptedData, 0, aesKey);

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

    public static byte[] DecryptFragmentCtr(byte[] encryptedData, byte[] rcCode)
        => DecryptFragmentCtrWithKey(encryptedData, DeriveKeyLegacy(rcCode));

    /// <summary>
    /// Decrypt a fragment (with optional 0xFF01 header) and strip the embedded index.
    /// Returns the raw fragment payload ready for FSS decoding or integrity checks.
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

    public static byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey)
        => EncryptFragmentWithKey(indexData, aesKey);

    public static byte[] EncryptIndex(byte[] indexData, byte[] rcCode)
        => EncryptIndexWithKey(indexData, DeriveKeyLegacy(rcCode));

    public static byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey)
        => DecryptFragmentWithKey(encryptedIndex, aesKey);

    public static byte[] DecryptIndex(byte[] encryptedIndex, byte[] rcCode)
        => DecryptIndexWithKey(encryptedIndex, DeriveKeyLegacy(rcCode));

    // ── Salt-prefixed index format (new) ──

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

    public static byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password)
        => EncryptIndexWithSaltPrefix(indexData, password, out _);

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

    private static bool IsValidCbor(byte[] data)
    {
        try
        {
            var reader = new CborReader(data);
            reader.ReadStartMap();
            // Verify at least one expected key exists (file_fingerprint or version)
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
