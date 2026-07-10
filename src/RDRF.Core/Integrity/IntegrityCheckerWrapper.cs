using RDRF.Core.Abstractions;

namespace RDRF.Core.Integrity;

public class IntegrityCheckerWrapper : IIntegrityChecker
{
    public string HashBytes(byte[] data) => IntegrityChecker.HashBytes(data);
    public string HashFile(string filePath) => IntegrityChecker.HashFile(filePath);
    public bool VerifyHash(string actualHash, string expectedHash) => IntegrityChecker.VerifyHash(actualHash, expectedHash);
    public bool VerifyFragment(byte[] fragmentData, string expectedHash) => IntegrityChecker.VerifyFragment(fragmentData, expectedHash);
    public bool BytesEqual(byte[]? a, byte[]? b) => IntegrityChecker.BytesEqual(a, b);
}
