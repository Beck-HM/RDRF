using RDRF.Core.Abstractions;

namespace RDRF.Core.Encryption;

public class EncryptionLayerWrapper : IEncryptionLayer
{
    public byte[] DeriveKeyLegacy(byte[] rcCode) => EncryptionLayer.DeriveKeyLegacy(rcCode);
    public (byte[] aesKey, byte[] cbor) DecryptIndexWithAutoDetect(byte[] encryptedIndex, byte[] rcCode)
        => EncryptionLayer.DecryptIndexWithAutoDetect(encryptedIndex, rcCode);
    public byte[] DeriveKey(byte[] rcCode, byte[] salt) => EncryptionLayer.DeriveKey(rcCode, salt);
    public byte[] GenerateRcCode(int length) => EncryptionLayer.GenerateRcCode(length);
    public int RcCodeLength => Constants.RcCodeLength;
}
