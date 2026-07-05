namespace RDRF.Core.Abstractions;

public interface IEncryptionLayer
{
    byte[] DeriveKeyLegacy(byte[] rcCode);
    (byte[] aesKey, byte[] cbor) DecryptIndexWithAutoDetect(byte[] encryptedIndex, byte[] rcCode);
    byte[] DeriveKey(byte[] rcCode, byte[] salt);
    byte[] GenerateRcCode(int length);
    int RcCodeLength { get; }
}
