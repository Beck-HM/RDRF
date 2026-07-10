namespace RDRF.Core.Abstractions;

public interface IIntegrityChecker
{
    string HashBytes(byte[] data);
    string HashFile(string filePath);
    bool VerifyHash(string actualHash, string expectedHash);
    bool VerifyFragment(byte[] fragmentData, string expectedHash);
    bool BytesEqual(byte[]? a, byte[]? b);
}
