using RDRF.Storage;

namespace RDRF.Plugins.Key;

public class KeyStorageBackendFactory : IStorageBackendFactory
{
    public string Type => "key";

    public IStorageBackend Create(Dictionary<string, object> config)
    {
        var endpoint = GetString(config, "endpoint");
        var bucket = GetString(config, "bucket");
        var accessKey = GetString(config, "access_key");
        var secretKey = GetString(config, "secret_key");
        var region = GetString(config, "region");

        if (string.IsNullOrEmpty(endpoint))
            throw new ArgumentException("endpoint is required for key backend");
        if (string.IsNullOrEmpty(bucket))
            throw new ArgumentException("bucket is required for key backend");
        if (string.IsNullOrEmpty(accessKey))
            throw new ArgumentException("access_key is required for key backend");
        if (string.IsNullOrEmpty(secretKey))
            throw new ArgumentException("secret_key is required for key backend");

        return new KeyStorageBackend(endpoint, bucket, accessKey, secretKey, region);
    }

    private static string GetString(Dictionary<string, object> config, string key)
    {
        if (config.TryGetValue(key, out var val) && val is string s)
            return s;
        return string.Empty;
    }
}
