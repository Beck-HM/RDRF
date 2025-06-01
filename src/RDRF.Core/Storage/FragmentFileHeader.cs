using RDRF.Core.Encryption;

namespace RDRF.Core.Storage;

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
        byte[] payload = new byte[4 + idxLen + fragmentData.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(idxLen), 0, payload, 0, 4);
        Buffer.BlockCopy(serializedIndex, 0, payload, 4, idxLen);
        Buffer.BlockCopy(fragmentData, 0, payload, 4 + idxLen, fragmentData.Length);

        bool hasSalt = salt != null && salt.Length == Constants.SaltPrefixLength;
        int headerSize = hasSalt ? HeaderSize + Constants.SaltPrefixLength : HeaderSize;
        byte[] header = new byte[headerSize];
        header[0] = 0xFF;
        header[1] = 0x01;
        header[2] = (byte)(hasSalt ? 2 : 1);
        header[3] = (byte)(hasSalt ? Constants.SaltPrefixLength : 0);
        header[4] = 0;
        header[5] = 0;

        if (hasSalt)
            Buffer.BlockCopy(salt!, 0, header, HeaderSize, Constants.SaltPrefixLength);

        byte[] encrypted = EncryptionLayer.EncryptFragmentCtrWithKey(payload, aesKey);

        byte[] result = new byte[header.Length + encrypted.Length];
        Buffer.BlockCopy(header, 0, result, 0, header.Length);
        Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
        return result;
    }

    public static (byte[]? embeddedIndex, byte[] fragmentData, byte[]? salt) DecryptWithEmbeddedIndex(
        byte[] fileData, byte[] aesKey)
    {
        bool hasHeader = HasHeader(fileData);
        int hdrOff = hasHeader ? GetTotalHeaderSize(fileData) : 0;

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
            if (idxLen > 4 && idxLen <= decrypted.Length - 4)
            {
                byte[] embeddedIdx = decrypted[4..(4 + idxLen)];
                byte[] fragData = decrypted[(4 + idxLen)..];
                return (embeddedIdx, fragData, salt);
            }
        }

        return (null, decrypted, salt);
    }
}
