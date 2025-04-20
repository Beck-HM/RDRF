using RDRF.Core.Encryption;

namespace RDRF.Core.Storage;

public static class FragmentFileHeader
{
    public const int AadAuthenticationVersion = 2;
    public const int HeaderSize = 6;

    public static bool HasHeader(byte[] data)
        => data.Length >= HeaderSize && data[0] == 0xFF && data[1] == 0x01;

    public static byte[] EncryptWithEmbeddedIndex(
        byte[] fragmentData, byte[] serializedIndex, byte[] aesKey, byte[] nonce, bool needsCtr)
    {
        // Format: embedded index (4B length + index bytes) followed by fragment data
        int idxLen = serializedIndex.Length;
        byte[] payload = new byte[4 + idxLen + fragmentData.Length];
        Buffer.BlockCopy(BitConverter.GetBytes(idxLen), 0, payload, 0, 4);
        Buffer.BlockCopy(serializedIndex, 0, payload, 4, idxLen);
        Buffer.BlockCopy(fragmentData, 0, payload, 4 + idxLen, fragmentData.Length);

        // Header: [FF][version(1)][ctr_flag(1)][0(1)][aad_version(1)][0(1)]
        byte[] header = new byte[HeaderSize];
        header[0] = 0xFF;
        header[1] = 0x01;
        header[2] = needsCtr ? (byte)1 : (byte)0;
        header[3] = 0;
        header[4] = AadAuthenticationVersion;
        header[5] = 0;

        byte[] encrypted;
        if (needsCtr)
        {
            encrypted = EncryptionLayer.EncryptFragmentCtrWithKey(payload, aesKey);
        }
        else
        {
            encrypted = EncryptionLayer.EncryptFragmentWithKey(payload, aesKey, nonce, associatedData: header);
        }

        byte[] result = new byte[header.Length + encrypted.Length];
        Buffer.BlockCopy(header, 0, result, 0, header.Length);
        Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
        return result;
    }

    public static (byte[]? embeddedIndex, byte[] fragmentData) DecryptWithEmbeddedIndex(
        byte[] fileData, byte[] aesKey, bool? needsCtrFromIndex = null)
    {
        bool hasHeader = HasHeader(fileData);
        bool needsCtr;

        if (hasHeader)
            needsCtr = fileData[2] == 1;
        else if (needsCtrFromIndex.HasValue)
            needsCtr = needsCtrFromIndex.Value;
        else
            throw new InvalidDataException("Cannot determine encryption mode.");

        int hdrOff = hasHeader ? HeaderSize : 0;

        byte[] decrypted;
        if (hasHeader && !needsCtr && fileData[4] >= AadAuthenticationVersion)
        {
            byte[] headerBytes = fileData[..HeaderSize];
            decrypted = EncryptionLayer.DecryptFragmentWithKey(fileData, hdrOff, aesKey, associatedData: headerBytes);
        }
        else
        {
            decrypted = needsCtr
                ? EncryptionLayer.DecryptFragmentCtrWithKey(fileData, hdrOff, aesKey)
                : EncryptionLayer.DecryptFragmentWithKey(fileData, hdrOff, aesKey);
        }

        if (hasHeader && decrypted.Length >= 4)
        {
            int idxLen = BitConverter.ToInt32(decrypted[0..4]);
            if (idxLen > 4 && idxLen <= decrypted.Length - 4)
            {
                byte[] embeddedIdx = decrypted[4..(4 + idxLen)];
                byte[] fragData = decrypted[(4 + idxLen)..];
                return (embeddedIdx, fragData);
            }
        }

        return (null, decrypted);
    }
}
