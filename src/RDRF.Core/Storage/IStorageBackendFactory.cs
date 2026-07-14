namespace RDRF.Core.DSAA;

public interface IStorageBackendFactory
{
    string Type { get; }

    IStorageBackend Create(Dictionary<string, object> config);
}
