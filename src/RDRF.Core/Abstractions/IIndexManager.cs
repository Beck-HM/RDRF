using RDRF.Core.Index;

namespace RDRF.Core.Abstractions;

/// <summary>
/// Serializes and deserializes backup index files in CBOR format.
/// </summary>
public interface IIndexManager
{
    /// <summary>Serializes an <see cref="RdrfIndex"/> to CBOR bytes.</summary>
    byte[] SerializeIndex(RdrfIndex index);

    /// <summary>Deserializes CBOR bytes back into an <see cref="RdrfIndex"/>.</summary>
    RdrfIndex DeserializeIndex(byte[] cbor);
}
