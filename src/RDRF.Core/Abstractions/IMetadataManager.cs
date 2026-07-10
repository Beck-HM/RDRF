namespace RDRF.Core.Abstractions;

public interface IMetadataManager
{
    void SaveBackup(string fileFingerprint, string originalFilename, long originalSize, string originalHash, string fssStrategy, List<string> fragmentHashes);
    void DeleteBackup(string fileFingerprint);
    void MarkFragmentOk(string fileFingerprint, int fragmentIndex);
    void MarkFragmentMissing(string fileFingerprint, int fragmentIndex);
    void MarkFragmentCorrupt(string fileFingerprint, int fragmentIndex);
    Dictionary<int, string> GetFragmentStatus(string fileFingerprint);
}
