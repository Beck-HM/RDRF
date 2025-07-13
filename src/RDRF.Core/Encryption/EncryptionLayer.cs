using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Core.Encryption;

public static class EncryptionLayer
{
    public static readonly byte[] PasswordSalt = Encoding.UTF8.GetBytes("RDRF.NET-PBKDF2-SALT-v1");

    private const int Pbkdf2Iterations = 600_000;
    private const int MinNewFormatSize = Constants.SaltPrefixLength + Constants.NonceLength + 1;

    public static byte[] DeriveKey(byte[] rcCode, byte[]? salt = null)
    {
        if (salt == null)
            return SHA256.HashData(rcCode);
        using var pbkdf2 = new Rfc2898DeriveBytes(rcCode, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

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

        return CtrCryptWithKey(ciphertext, aesKey, nonce);
    }

    private static byte[] CtrCryptWithKey(byte[] data, byte[] aesKey, byte[] nonce)
    {
        byte[] output = new byte[data.Length];
        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] counter = new byte[16];
        Buffer.BlockCopy(nonce, 0, counter, 0, Math.Min(nonce.Length, 12));
        counter[15] = 1;

        byte[] keystreamBlock = new byte[16];
        using var encryptor = aes.CreateEncryptor();

        for (int i = 0; i < data.Length; i += 16)
        {
            encryptor.TransformBlock(counter, 0, 16, keystreamBlock, 0);
            int blockLen = Math.Min(16, data.Length - i);
            for (int j = 0; j < blockLen; j++)
                output[i + j] = (byte)(data[i + j] ^ keystreamBlock[j]);
            IncrementCounter(counter);
        }
        return output;
    }

    private static void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0) break;
        }
    }

    private static byte[] CtrCrypt(byte[] data, byte[] rcCode, byte[] nonce)
        => CtrCryptWithKey(data, DeriveKey(rcCode), nonce);

    public static void CtrTransformStream(Stream input, Stream output, byte[] aesKey, byte[] nonce)
    {
        byte[] counter = new byte[16];
        Buffer.BlockCopy(nonce, 0, counter, 0, Math.Min(nonce.Length, 12));
        counter[15] = 1;

        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        byte[] keystreamBlock = new byte[16];
        byte[] buffer = new byte[81920];
        int bytesRead;

        while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int offset = 0; offset < bytesRead; offset += 16)
            {
                encryptor.TransformBlock(counter, 0, 16, keystreamBlock, 0);
                int blockLen = Math.Min(16, bytesRead - offset);
                for (int j = 0; j < blockLen; j++)
                    buffer[offset + j] ^= keystreamBlock[j];
                IncrementCounter(counter);
            }
            output.Write(buffer, 0, bytesRead);
        }
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
        => EncryptFragmentCtrWithKey(plaintext, DeriveKey(rcCode));

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

        return CtrCryptWithKey(ciphertext, aesKey, nonce);
    }

    public static byte[] DecryptFragmentCtr(byte[] encryptedData, byte[] rcCode)
        => DecryptFragmentCtrWithKey(encryptedData, DeriveKey(rcCode));

    public static byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey)
        => EncryptFragmentWithKey(indexData, aesKey);

    public static byte[] EncryptIndex(byte[] indexData, byte[] rcCode)
        => EncryptIndexWithKey(indexData, DeriveKey(rcCode));

    public static byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey)
        => DecryptFragmentWithKey(encryptedIndex, aesKey);

    public static byte[] DecryptIndex(byte[] encryptedIndex, byte[] rcCode)
        => DecryptIndexWithKey(encryptedIndex, DeriveKey(rcCode));

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

        byte[] legacyKey = DeriveKey(password);
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
