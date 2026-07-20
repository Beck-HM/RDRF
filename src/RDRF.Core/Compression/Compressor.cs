namespace RDRF.Core.Compression;

public static class Compressor
{
    private static readonly Lazy<CompressionRouter> _router = new(() => new CompressionRouter());
    internal static CompressionRouter? RouterOverride;

    private static CompressionRouter Router => RouterOverride ?? _router.Value;

    public static bool IsLz4Frame(byte[] data) => new Lz4Algorithm().CanHandle(data);

    public static byte[] AlwaysCompress(byte[] data, string? method = null, string? options = null)
        => Router.AlwaysCompress(data, method ?? Constants.CompressionLz4, options);

    public static byte[] Compress(byte[] data, string? method = null, string? options = null)
        => Router.Compress(data, method ?? Constants.CompressionLz4, options);

    public static byte[] Decompress(byte[] data, string? method)
        => Router.Decompress(data, method);
}
