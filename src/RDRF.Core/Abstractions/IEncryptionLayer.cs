namespace RDRF.Core.Abstractions;

public interface IEncryptionLayer
{
    byte[] DeriveKey(byte[] rcCode, byte[] salt);
    byte[] DeriveKeyLegacy(byte[] rcCode);
    byte[] GenerateRcCode(int length = 64);
    byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey);
    byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey);
    byte[] DecryptAndStripFragment(byte[] encryptedData, byte[] aesKey);
    byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey);
    byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey);
    (byte[] aesKey, byte[] indexCbor) DecryptIndexWithAutoDetect(byte[] data, byte[] password);
    byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password, byte[]? existingSalt = null);
    byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey);
    byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey);
}
