namespace RDRF.Core.Abstractions;

/// <summary>
/// AES-256-CTR encryption layer for fragments and index files.
/// Supports both PBKDF2-based key derivation and legacy SHA256 fallback.
/// </summary>
public interface IEncryptionLayer
{
    /// <summary>Derives an AES key using PBKDF2 with the given recovery code and salt.</summary>
    byte[] DeriveKey(byte[] rcCode, byte[] salt);

    /// <summary>Derives an AES key using the legacy SHA256 path (no salt).</summary>
    byte[] DeriveKeyLegacy(byte[] rcCode);

    /// <summary>Generates a cryptographically random recovery code.</summary>
    byte[] GenerateRcCode(int length = 64);

    /// <summary>Encrypts a plaintext fragment with the given AES key.</summary>
    byte[] EncryptFragmentWithKey(byte[] plaintext, byte[] aesKey);

    /// <summary>Decrypts an encrypted fragment with the given AES key.</summary>
    byte[] DecryptFragmentWithKey(byte[] encryptedData, byte[] aesKey);

    /// <summary>Decrypts a fragment and strips the padding trailer.</summary>
    byte[] DecryptAndStripFragment(byte[] encryptedData, byte[] aesKey);

    /// <summary>Encrypts index CBOR data with the given AES key.</summary>
    byte[] EncryptIndexWithKey(byte[] indexData, byte[] aesKey);

    /// <summary>Decrypts an encrypted index with the given AES key.</summary>
    byte[] DecryptIndexWithKey(byte[] encryptedIndex, byte[] aesKey);

    /// <summary>Auto-detects PBKDF2 salt vs. legacy SHA256 format and decrypts the index.</summary>
    (byte[] aesKey, byte[] indexCbor) DecryptIndexWithAutoDetect(byte[] data, byte[] password);

    /// <summary>Encrypts index data with a PBKDF2 salt prefix.</summary>
    byte[] EncryptIndexWithSaltPrefix(byte[] indexData, byte[] password, byte[]? existingSalt = null);

    /// <summary>Encrypts a fragment using AES-256-CTR mode with the given key.</summary>
    byte[] EncryptFragmentCtrWithKey(byte[] plaintext, byte[] aesKey);

    /// <summary>Decrypts a fragment encrypted with AES-256-CTR mode.</summary>
    byte[] DecryptFragmentCtrWithKey(byte[] encryptedData, byte[] aesKey);
}
