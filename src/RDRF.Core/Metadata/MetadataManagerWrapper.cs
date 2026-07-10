using System;
using RDRF.Core.Abstractions;

namespace RDRF.Core.Metadata;

public class MetadataManagerWrapper : IMetadataManager
{
    private readonly MetadataManager _inner;

    public MetadataManagerWrapper()
    {
        _inner = new MetadataManager(null, skipLoad: true);
    }

    public MetadataManagerWrapper(MetadataManager inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public void SaveBackup(string fileFingerprint, string originalFilename, long originalSize, string originalHash, string fssStrategy, List<string> fragmentHashes)
        => _inner.SaveBackup(fileFingerprint, originalFilename, originalSize, originalHash, fssStrategy, fragmentHashes);
    public void DeleteBackup(string fileFingerprint) => _inner.DeleteBackup(fileFingerprint);
    public void MarkFragmentOk(string fileFingerprint, int fragmentIndex) => _inner.MarkFragmentOk(fileFingerprint, fragmentIndex);
    public void MarkFragmentMissing(string fileFingerprint, int fragmentIndex) => _inner.MarkFragmentMissing(fileFingerprint, fragmentIndex);
    public void MarkFragmentCorrupt(string fileFingerprint, int fragmentIndex) => _inner.MarkFragmentCorrupt(fileFingerprint, fragmentIndex);
    public Dictionary<int, string> GetFragmentStatus(string fileFingerprint) => _inner.GetFragmentStatus(fileFingerprint);
}

