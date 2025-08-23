using RDRF.Dssa;

namespace RDRF.Plugins.Rest;

public class RestStorageBackendFactory : IStorageBackendFactory
{
    public string Type => "rest";

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        var apiUrl = GetString(config, "api_url");
        var token = GetString(config, "token");

        if (string.IsNullOrEmpty(apiUrl))
            throw new ArgumentException("api_url is required for rest backend");
        if (string.IsNullOrEmpty(token))
            throw new ArgumentException("token is required for rest backend");

        return new RestStorageBackend(apiUrl, token);
    }

    private static string GetString(Dictionary<string, object> config, string key)
    {
        if (config.TryGetValue(key, out var val) && val is string s)
            return s;
        return string.Empty;
    }
}