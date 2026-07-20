using RDRF.Core.Encryption;

namespace RDRF.Core.DSAA;

/// <summary>
/// Fragment file header (magic + metadata) and EncryptWithEmbeddedIndex logic.
/// </summary>

public static class FragmentFileHeader
{
    public const int HeaderSize = 6;

    public static bool HasHeader(byte[] data)
        => data.Length >= HeaderSize && data[0] == 0xFF && data[1] == 0x01;

    public static int GetTotalHeaderSize(byte[] data)
    {
        if (!HasHeader(data) || data.Length < 3)
            return 0;
        if (data[2] >= 2 && data.Length >= 7)
        {
            int saltLen = data[3];
            return HeaderSize + saltLen;
        }
        return HeaderSize;
    }

    public static byte[] EncryptWithEmbeddedIndex(
        byte[] fragmentData, byte[] serializedIndex, byte[] aesKey, byte[]? salt = null)
    {
        int idxLen = serializedIndex.Length;
        int payloadLen = 4 + idxLen + fragmentData.Length;
        bool hasSalt = salt != null && salt.Length == Constants.SaltPrefixLength;
        int headerSize = hasSalt ? HeaderSize + Constants.SaltPrefixLength : HeaderSize;
        int nonceLen = Constants.NonceLength;

        // One allocation: header || nonce || ciphertext (CTR encrypts payload in place).
        byte[] result = new byte[headerSize + nonceLen + payloadLen];
        result[0] = 0xFF;
        result[1] = 0x01;
        result[2] = (byte)(hasSalt ? 2 : 1);
        result[3] = (byte)(hasSalt ? Constants.SaltPrefixLength : 0);
        result[4] = Crc8(result, 0, 4);
        result[5] = 0;
        if (hasSalt)
            Buffer.BlockCopy(salt!, 0, result, HeaderSize, Constants.SaltPrefixLength);

        int payloadOff = headerSize + nonceLen;
        BitConverter.TryWriteBytes(result.AsSpan(payloadOff, 4), idxLen);
        Buffer.BlockCopy(serializedIndex, 0, result, payloadOff + 4, idxLen);
        Buffer.BlockCopy(fragmentData, 0, result, payloadOff + 4 + idxLen, fragmentData.Length);

        byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(nonceLen);
        Buffer.BlockCopy(nonce, 0, result, headerSize, nonceLen);
        // In-place CTR over payload region (same as EncryptFragmentCtrWithKey wire layout).
        Encryption.AesNiCtr.CtrCrypt(
            result.AsSpan(payloadOff, payloadLen),
            result.AsSpan(payloadOff, payloadLen),
            aesKey,
            nonce);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(nonce);
        return result;
    }

    /// <summary>
    /// Encrypt with embedded index and write to a stream (header || nonce || ciphertext).
    /// Uses a rented payload buffer that is returned after write so the caller need not hold
    /// a long-lived full-file ciphertext array.
    /// </summary>
    public static async Task EncryptWithEmbeddedIndexToStreamAsync(
        Stream output, byte[] fragmentData, byte[] serializedIndex, byte[] aesKey,
        byte[]? salt = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(fragmentData);
        ArgumentNullException.ThrowIfNull(serializedIndex);
        ArgumentNullException.ThrowIfNull(aesKey);

        int idxLen = serializedIndex.Length;
        int payloadLen = 4 + idxLen + fragmentData.Length;
        bool hasSalt = salt != null && salt.Length == Constants.SaltPrefixLength;
        int headerSize = hasSalt ? HeaderSize + Constants.SaltPrefixLength : HeaderSize;
        int nonceLen = Constants.NonceLength;

        // Header (small, stack/local)
        byte[] header = new byte[headerSize];
        header[0] = 0xFF;
        header[1] = 0x01;
        header[2] = (byte)(hasSalt ? 2 : 1);
        header[3] = (byte)(hasSalt ? Constants.SaltPrefixLength : 0);
        header[4] = Crc8(header, 0, 4);
        header[5] = 0;
        if (hasSalt)
            Buffer.BlockCopy(salt!, 0, header, HeaderSize, Constants.SaltPrefixLength);
        await output.WriteAsync(header.AsMemory(0, headerSize), ct).ConfigureAwait(false);

        byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(nonceLen);
        await output.WriteAsync(nonce.AsMemory(0, nonceLen), ct).ConfigureAwait(false);

        // Rent payload only for CTR; write then return (no long-lived ciphertext array).
        byte[] payload = System.Buffers.ArrayPool<byte>.Shared.Rent(payloadLen);
        try
        {
            BitConverter.TryWriteBytes(payload.AsSpan(0, 4), idxLen);
            Buffer.BlockCopy(serializedIndex, 0, payload, 4, idxLen);
            Buffer.BlockCopy(fragmentData, 0, payload, 4 + idxLen, fragmentData.Length);
            Encryption.AesNiCtr.CtrCrypt(
                payload.AsSpan(0, payloadLen),
                payload.AsSpan(0, payloadLen),
                aesKey,
                nonce);
            await output.WriteAsync(payload.AsMemory(0, payloadLen), ct).ConfigureAwait(false);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(payload.AsSpan(0, payloadLen));
            System.Buffers.ArrayPool<byte>.Shared.Return(payload, clearArray: false);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(nonce);
        }
    }

    public static (byte[]? embeddedIndex, byte[] fragmentData, byte[]? salt) DecryptWithEmbeddedIndex(
        byte[] fileData, byte[] aesKey)
    {
        bool hasHeader = HasHeader(fileData);
        int hdrOff = hasHeader ? GetTotalHeaderSize(fileData) : 0;

        if (hasHeader && fileData.Length >= HeaderSize && (fileData[4] != 0 || fileData[5] != 0)
            && fileData[4] != Crc8(fileData, 0, 4))
            throw new InvalidDataException("Fragment header CRC8 mismatch: header may be corrupted.");

        byte[]? salt = null;
        if (hasHeader && fileData.Length >= HeaderSize + Constants.SaltPrefixLength && fileData[2] >= 2 && fileData[3] == Constants.SaltPrefixLength)
        {
            salt = new byte[Constants.SaltPrefixLength];
            Buffer.BlockCopy(fileData, HeaderSize, salt, 0, Constants.SaltPrefixLength);
        }

        byte[] decrypted = EncryptionLayer.DecryptFragmentCtrWithKey(fileData, hdrOff, aesKey);

        if (hasHeader && decrypted.Length >= 4)
        {
            int idxLen = BitConverter.ToInt32(decrypted[0..4]);
            if (idxLen > 0 && idxLen <= decrypted.Length - 4)
            {
                byte[] embeddedIdx = decrypted[4..(4 + idxLen)];
                byte[] fragData = decrypted[(4 + idxLen)..];
                return (embeddedIdx, fragData, salt);
            }
        }

        return (null, decrypted, salt);
    }

    private static byte Crc8(byte[] data, int offset, int length)
    {
        byte crc = 0;
        for (int i = offset; i < offset + length; i++)
        {
            crc ^= data[i];
            for (int j = 0; j < 8; j++)
                crc = (byte)((crc & 0x80) != 0 ? (crc << 1) ^ 0x07 : crc << 1);
        }
        return crc;
    }
}

