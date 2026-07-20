using System.Collections.Concurrent;

namespace RDRF.Core.Compression;

public class CompressionRouter
{
    private readonly ConcurrentDictionary<string, ICompressionAlgorithm> _algorithms = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ICompressionAlgorithm> _registrationOrder = new();
    private string _defaultMethod = Constants.CompressionLz4;
    private static readonly HashSet<string> CompressedMagic = new(StringComparer.OrdinalIgnoreCase)
    {
        "ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "ffd8ffe3", "ffd8ffe8",
        "89504e47", "47494638", "504b0304", "504b0506", "504b0708",
        "1f8b08", "52617221", "377abcaf271c", "494433", "664c6143", "4d546864",
    };

    public CompressionRouter()
    {
        Register(new Lz4Algorithm());
        Register(new Lz4HcAlgorithm());
        Register(new ZstdAlgorithm());
        Register(new GzipAlgorithm());
        Register(new BrotliAlgorithm());
        Register(new LzmaAlgorithm());
        Register(new LzoAlgorithm());
        Register(new XzAlgorithm());
        Register(new Ckc.CkcAlgorithm());
        if (OperatingSystem.IsWindows())
        {
            Register(new XpressHuffAlgorithm());
            Register(new LzmsAlgorithm());
        }
    }

    public void Register(ICompressionAlgorithm algorithm)
    {
        _algorithms[algorithm.Name] = algorithm;
        _registrationOrder.Add(algorithm);
    }

    public byte[] Compress(byte[] data, string? method, string? options = null)
    {
        if (string.IsNullOrEmpty(method) || !_algorithms.TryGetValue(method, out var algo))
            return data;
        if (IsProbablyCompressed(data))
            return data;
        byte[] compressed = algo.Compress(data, options);
        return compressed.Length < data.Length ? compressed : data;
    }

    public byte[] Decompress(byte[] data, string? method)
    {
        if (string.IsNullOrEmpty(method) || !_algorithms.TryGetValue(method, out var algo))
            return data;
        if (!algo.CanHandle(data))
            return data;
        return algo.Decompress(data);
    }

    public ICompressionAlgorithm? Detect(byte[] data)
    {
        foreach (var algo in _registrationOrder)
            if (algo.CanHandle(data))
                return algo;
        return null;
    }

    public byte[] AlwaysCompress(byte[] data, string? method = null, string? options = null)
    {
        if (IsProbablyCompressed(data))
            return data;
        string m = method ?? _defaultMethod;
        if (_algorithms.TryGetValue(m, out var algo))
            return algo.Compress(data, options);
        return data;
    }

    private static bool IsProbablyCompressed(byte[] data)
    {
        if (data.Length < 4) return false;
        string hex = Convert.ToHexString(data.AsSpan(0, Math.Min(16, data.Length)));
        foreach (string magic in CompressedMagic)
            if (hex.StartsWith(magic, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
