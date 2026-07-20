using RDRF.Core.DSAA;

internal sealed class RdrfBackendFactory : IStorageBackendFactory
{
    public string Type => "rdrf";

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        string name = config.TryGetValue("name", out var n) ? n?.ToString() ?? "rdrf" : "rdrf";
        string host = config.TryGetValue("host", out var h) ? h?.ToString() ?? throw new ArgumentException("Missing host") : throw new ArgumentException("Missing host");
        int port = config.TryGetValue("port", out var p) && int.TryParse(p?.ToString(), out int portVal) ? portVal : 8080;
        return new RdrfNativeBackend(name, host, port);
    }
}
