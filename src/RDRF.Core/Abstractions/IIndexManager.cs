using RDRF.Core.Index;

namespace RDRF.Core.Abstractions;

public interface IIndexManager
{
    byte[] SerializeIndex(RdrfIndex index);
    RdrfIndex DeserializeIndex(byte[] cbor);
}
