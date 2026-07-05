using RDRF.Core.Abstractions;

namespace RDRF.Core.Index;

public class IndexManagerWrapper : IIndexManager
{
    public byte[] SerializeIndex(RdrfIndex index) => IndexManager.SerializeIndex(index);
    public RdrfIndex DeserializeIndex(byte[] cbor) => IndexManager.DeserializeIndex(cbor);
}
