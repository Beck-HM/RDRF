using System.Runtime.InteropServices;

namespace RDRF.Core.Compression;

public class XpressHuffAlgorithm : ICompressionAlgorithm
{
    private const uint COMPRESS_ALGORITHM_XPRESS_HUFF = 4;

    public string Name => Constants.CompressionXpressHuff;

    [DllImport("cabinet.dll")]
    private static extern bool CreateCompressor(uint Algorithm, IntPtr AllocationRoutines, out IntPtr CompressorHandle);

    [DllImport("cabinet.dll")]
    private static extern bool Compress(IntPtr CompressorHandle, byte[] UncompressedData, UIntPtr UncompressedDataSize, byte[] CompressedBuffer, UIntPtr CompressedBufferSize, out UIntPtr CompressedDataSize);

    [DllImport("cabinet.dll")]
    private static extern bool CreateDecompressor(uint Algorithm, IntPtr AllocationRoutines, out IntPtr DecompressorHandle);

    [DllImport("cabinet.dll")]
    private static extern bool Decompress(IntPtr DecompressorHandle, byte[] CompressedData, UIntPtr CompressedDataSize, byte[] UncompressedBuffer, UIntPtr UncompressedBufferSize, out UIntPtr UncompressedDataSize);

    [DllImport("cabinet.dll")]
    private static extern bool CloseCompressor(IntPtr CompressorHandle);

    [DllImport("cabinet.dll")]
    private static extern bool CloseDecompressor(IntPtr DecompressorHandle);

    public byte[] Compress(byte[] data, string? options = null)
    {
        AssumeWindows();
        CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, IntPtr.Zero, out var handle);
        try
        {
            var us = (UIntPtr)(uint)data.Length;
            int bufSize = data.Length + 65536;
            var buf = new byte[bufSize];
            var cbs = new UIntPtr((uint)bufSize);
            if (!Compress(handle, data, us, buf, cbs, out var cs))
                throw new InvalidDataException("XPRESS_HUFF compression failed");
            byte[] result = new byte[8 + (uint)cs];
            BitConverter.GetBytes(data.Length).CopyTo(result, 0);
            BitConverter.GetBytes((uint)cs).CopyTo(result, 4);
            Array.Copy(buf, 0, result, 8, (uint)cs);
            return result;
        }
        finally { CloseCompressor(handle); }
    }

    public byte[] Decompress(byte[] data)
    {
        AssumeWindows();
        int originalSize = BitConverter.ToInt32(data, 0);
        int compressedSize = BitConverter.ToInt32(data, 4);
        CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, IntPtr.Zero, out var handle);
        try
        {
            var cs = (UIntPtr)(uint)compressedSize;
            var us = (UIntPtr)(uint)originalSize;
            var buf = new byte[originalSize];
            if (!Decompress(handle, data[8..(8 + compressedSize)], cs, buf, us, out _))
                throw new InvalidDataException("XPRESS_HUFF decompression failed");
            return buf;
        }
        finally { CloseDecompressor(handle); }
    }

    public bool CanHandle(byte[] data) => data.Length >= 12;

    private static void AssumeWindows()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new PlatformNotSupportedException("XPRESS_HUFF requires Windows");
    }
}
