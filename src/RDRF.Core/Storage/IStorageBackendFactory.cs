namespace RDRF.Storage;

public interface IStorageBackendFactory
{
    string Type { get; }

    IStorageBackend Create(Dictionary<string, object> config);
}
