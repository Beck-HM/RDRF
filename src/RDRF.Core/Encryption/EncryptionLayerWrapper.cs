using RDRF.Core.Abstractions;

namespace RDRF.Core.Encryption;

public class EncryptionLayerWrapper : IEncryptionLayer
{
    public byte[] DeriveKey(byte[] rcCode, byte[] salt) => EncryptionLayer.DeriveKey(rcCode, salt);
    public byte[] DeriveKeyLegacy(byte[] rcCode) => EncryptionLayer.DeriveKeyLegacy(rcCode);
    public byte[] GenerateRcCode(int length = 64) => EncryptionLayer.GenerateRcCode(length);
    public byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey) => EncryptionLayer.EncryptFragmentWithKey(plaintext, aesKey);
    public byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey) => EncryptionLayer.DecryptFragmentWithKey(encryptedData, aesKey);
    public byte[] DecryptAndStripFragment(byte[] encryptedData, byte[] aesKey) => EncryptionLayer.DecryptAndStripFragment(encryptedData, aesKey);
    public byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey) => EncryptionLayer.EncryptIndexWithKey(indexData, aesKey);
    public byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey) => EncryptionLayer.DecryptIndexWithKey(encryptedIndex, aesKey);
    public (byte[] aesKey, byte[] indexCbor) DecryptIndexWithAutoDetect(byte[] data, byte[] password)
        => EncryptionLayer.DecryptIndexWithAutoDetect(data, password);
    public byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password, byte[]? existingSalt = null)
        => EncryptionLayer.EncryptIndexWithSaltPrefix(indexData, password, existingSalt);
    public byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey) => EncryptionLayer.EncryptFragmentCtrWithKey(plaintext, aesKey);
    public byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey) => EncryptionLayer.DecryptFragmentCtrWithKey(encryptedData, aesKey);
}
