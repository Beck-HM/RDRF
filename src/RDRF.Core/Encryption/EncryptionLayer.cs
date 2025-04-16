using System.Security.Cryptography;
using System.Text;

namespace RDRF.Core.Encryption;

public static class EncryptionLayer
{
    public static readonly byte[] PasswordSalt = Encoding.UTF8.GetBytes("RDRF.NET-PBKDF2-SALT-v1");

    private const int Pbkdf2Iterations = 600_000;

    public static byte[] DeriveKey(byte[] rcCode, byte[]? salt = null)
    {
        if (salt == null)
            return SHA256.HashData(rcCode);
        using var pbkdf2 = new Rfc2898DeriveBytes(rcCode, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    public static byte[] GenerateRcCode(int length = 64)
        => RandomNumberGenerator.GetBytes(length);

    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey, byte[]? associatedData = null)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(Constants.NonceLength);
        return EncryptFragmentWithKey(plaintext, aesKey, nonce, associatedData);
    }

    public static byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey, byte[] nonce, byte[]? associatedData = null)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.TagLength];

        using var aes = new AesGcm(aesKey, Constants.TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] result = new byte[Constants.NonceLength + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + ciphertext.Length, tag.Length);
        return result;
    }

    public static byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey, byte[]? associatedData = null)
    {
        int nonceLen = Constants.NonceLength;
        int tagLen = Constants.TagLength;
        int ciphertextLen = encryptedData.Length - nonceLen - tagLen;
        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted data length.");

        byte[] nonce = new byte[nonceLen];
        byte[] ciphertext = new byte[ciphertextLen];
        byte[] tag = new byte[tagLen];

        Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(encryptedData, nonceLen, ciphertext, 0, ciphertextLen);
        Buffer.BlockCopy(encryptedData, nonceLen + ciphertextLen, tag, 0, tagLen);

        byte[] plaintext = new byte[ciphertextLen];
        using var aes = new AesGcm(aesKey, Constants.TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
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

    [Obsolete("CTR mode lacks authentication. Use GCM (EncryptFragmentWithKey) for new backups.")]
    public static byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(Constants.NonceLength);
        byte[] ciphertext = CtrCryptWithKey(plaintext, aesKey, nonce);
        byte[] hmac = HMACSHA256.HashData(aesKey, ciphertext);
        byte[] result = new byte[nonce.Length + ciphertext.Length + hmac.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, result, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(hmac, 0, result, nonce.Length + ciphertext.Length, hmac.Length);
        return result;
    }

    public static byte[] EncryptFragmentCtr(byte[] plaintext, byte[] rcCode)
        => EncryptFragmentCtrWithKey(plaintext, DeriveKey(rcCode));

    public static byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey)
    {
        int nonceLen = Constants.NonceLength;
        const int hmacLen = 32;
        int ciphertextLen = encryptedData.Length - nonceLen - hmacLen;
        if (ciphertextLen < 0)
            throw new CryptographicException("Invalid encrypted data length for CTR mode.");

        byte[] nonce = new byte[nonceLen];
        byte[] ciphertext = new byte[ciphertextLen];
        byte[] storedHmac = new byte[hmacLen];
        Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(encryptedData, nonceLen, ciphertext, 0, ciphertextLen);
        Buffer.BlockCopy(encryptedData, nonceLen + ciphertextLen, storedHmac, 0, hmacLen);

        byte[] computedHmac = HMACSHA256.HashData(aesKey, ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac))
            throw new CryptographicException("CTR HMAC verification failed.");

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
}
