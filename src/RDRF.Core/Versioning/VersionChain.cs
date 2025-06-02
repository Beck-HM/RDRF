using System.Security.Cryptography;

namespace RDRF.Core.Versioning;

public class VersionChain
{
    private readonly string _rootPath;
    private VersionChainConfig? _config;

    public string RootPath => _rootPath;
    public VersionChainConfig Config => _config ?? throw new InvalidOperationException("VersionChain not initialized.");

    private VersionChain(string rootPath)
    {
        _rootPath = rootPath;
    }

    public static VersionChain Init(string rootPath)
    {
        Directory.CreateDirectory(rootPath);
        var chain = new VersionChain(rootPath);
        var salt = RandomNumberGenerator.GetBytes(Constants.SaltPrefixLength);
        chain._config = new VersionChainConfig
        {
            Salt = salt,
            KdfIterations = 600_000,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        File.WriteAllBytes(Path.Combine(rootPath, "config"), chain._config.Serialize());
        chain.WriteHead(0);
        return chain;
    }

    public static VersionChain Load(string rootPath)
    {
        if (!Directory.Exists(rootPath))
            throw new DirectoryNotFoundException($"Version chain not found at: {rootPath}");
        var configPath = Path.Combine(rootPath, "config");
        if (!File.Exists(configPath))
            throw new FileNotFoundException($"Config not found at: {configPath}");
        var chain = new VersionChain(rootPath);
        chain._config = VersionChainConfig.Deserialize(File.ReadAllBytes(configPath));
        return chain;
    }

    public static bool Exists(string rootPath)
    {
        return Directory.Exists(rootPath) && File.Exists(Path.Combine(rootPath, "config"));
    }

    public void WriteHead(int versionNumber)
    {
        File.WriteAllText(Path.Combine(_rootPath, "HEAD"), versionNumber.ToString());
    }

    public void WriteHead(int versionNumber, string fingerprint)
    {
        File.WriteAllText(Path.Combine(_rootPath, "HEAD"), $"{versionNumber}\n{fingerprint}");
    }

    public int ReadHead()
    {
        var parts = ReadHeadPair();
        return parts.version;
    }

    public int ReadHeadVersion()
    {
        return ReadHead();
    }

    public string ReadHeadFingerprint()
    {
        var parts = ReadHeadPair();
        return parts.fingerprint;
    }

    private (int version, string fingerprint) ReadHeadPair()
    {
        var headPath = Path.Combine(_rootPath, "HEAD");
        if (!File.Exists(headPath))
            return (0, string.Empty);
        var lines = File.ReadAllLines(headPath);
        int version = 0;
        if (lines.Length >= 1)
            version = int.TryParse(lines[0].Trim(), out var v) ? v : 0;
        string fingerprint = lines.Length >= 2 ? lines[1].Trim() : string.Empty;
        return (version, fingerprint);
    }
}
