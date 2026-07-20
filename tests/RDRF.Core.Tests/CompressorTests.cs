using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using RDRF.Core.Compression;
using RDRF.Core.Compression.Ckc;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

public class CompressorTests
{
    private readonly ITestOutputHelper? _output;

    public CompressorTests(ITestOutputHelper output) { _output = output; }
    [Fact]
    public void RoundTrip_TextData()
    {
        // 500 bytes of repeated text (LZ4-friendly)
        var data = new byte[500];
        byte[] pattern = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog. ");
        for (int i = 0; i < data.Length; i++)
            data[i] = pattern[i % pattern.Length];
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void EmptyData()
    {
        byte[] data = [];
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void AlreadyCompressed_JpegMagic_SkipsLz4()
    {
        // FF D8 FF E0 = JPEG start marker
        byte[] data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AlreadyCompressed_ZipMagic_SkipsLz4()
    {
        // PK\x03\x04 = ZIP start
        byte[] data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AlreadyCompressed_GzipMagic_SkipsLz4()
    {
        // 1F 8B 08 = GZIP
        byte[] data = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.Equal(data, result);
    }

    [Fact]
    public void AntiExpansion_IncompressibleData_ReturnsOriginal()
    {
        // Truly random data should not expand; but if LZ4 output is larger,
        // Compress should return the original
        var data = new byte[1000];
        System.Random.Shared.NextBytes(data);
        byte[] result = Compressor.Compress(data, Constants.CompressionLz4);
        Assert.True(result.Length <= data.Length || result == data);
    }

    [Fact]
    public void NullMethod_ReturnsOriginal()
    {
        byte[] data = [1, 2, 3, 4, 5];
        byte[] result = Compressor.Compress(data, null);
        Assert.Equal(data, result);
    }

    [Fact]
    public void LargeData_RoundTrip()
    {
        // Highly compressible pattern (repeating sequence)
        var data = new byte[100_000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = Compressor.Compress(data, Constants.CompressionLz4);
        byte[] decompressed = Compressor.Decompress(compressed, Constants.CompressionLz4);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void Decompress_NoCompression_ReturnsAsIs()
    {
        byte[] data = [10, 20, 30, 40, 50];
        byte[] result = Compressor.Decompress(data, null);
        Assert.Equal(data, result);
    }

    // -- Lz4Algorithm direct tests --

    [Fact]
    public void Lz4Algorithm_RoundTrip()
    {
        var algo = new Lz4Algorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = algo.Compress(data);
        Assert.True(algo.CanHandle(compressed));
        byte[] decompressed = algo.Decompress(compressed);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void Lz4Algorithm_CanHandle_DetectsMagic()
    {
        var algo = new Lz4Algorithm();
        var lz4Frame = new byte[] { 0x04, 0x22, 0x4D, 0x18, 0x60, 0x00, 0x00, 0x00 };
        Assert.True(algo.CanHandle(lz4Frame));
        Assert.False(algo.CanHandle(new byte[] { 0x00, 0x00, 0x00, 0x00 }));
        Assert.False(algo.CanHandle(Array.Empty<byte>()));
    }

    // -- CompressionRouter direct tests --

    [Fact]
    public void CompressionRouter_RegisterAndDispatch()
    {
        var router = new CompressionRouter();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] result = router.Compress(data, Constants.CompressionLz4);
        Assert.True(result.Length > 0);
        Assert.True(new Lz4Algorithm().CanHandle(result));
        byte[] back = router.Decompress(result, Constants.CompressionLz4);
        Assert.Equal(data, back);
    }

    [Fact]
    public void CompressionRouter_UnknownMethod_ReturnsOriginal()
    {
        var router = new CompressionRouter();
        byte[] data = [1, 2, 3, 4, 5];
        Assert.Equal(data, router.Compress(data, "nonexistent"));
        Assert.Equal(data, router.Decompress(data, "nonexistent"));
    }

    [Fact]
    public void CompressionRouter_NullMethod_ReturnsOriginal()
    {
        var router = new CompressionRouter();
        byte[] data = [1, 2, 3, 4, 5];
        Assert.Equal(data, router.Compress(data, null));
        Assert.Equal(data, router.Decompress(data, null));
        Assert.Equal(data, router.Compress(data, ""));
        Assert.Equal(data, router.Decompress(data, ""));
    }

    [Fact]
    public void CompressionRouter_AlwaysCompress_DefaultsToLz4()
    {
        var router = new CompressionRouter();
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 256);
        byte[] result = router.AlwaysCompress(data, Constants.CompressionLz4);
        Assert.True(result.Length < data.Length);
        Assert.True(new Lz4Algorithm().CanHandle(result));
    }

    [Fact]
    public void CompressionRouter_Detect_MatchesAlgorithm()
    {
        var router = new CompressionRouter();
        var algo = new Lz4Algorithm();
        byte[] compressed = algo.Compress("test"u8.ToArray());
        var detected = router.Detect(compressed);
        Assert.NotNull(detected);
        Assert.Equal("lz4", detected!.Name);
    }

    // -- AlwaysCompress + IsLz4Frame tests --

    [Fact]
    public void AlwaysCompress_Compressible_ReturnsLz4Frame()
    {
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 256);
        byte[] compressed = Compressor.AlwaysCompress(data);
        Assert.True(compressed.Length < data.Length);
        Assert.True(Compressor.IsLz4Frame(compressed));
    }

    [Fact]
    public void AlwaysCompress_Incompressible_StillProducesLz4Frame()
    {
        // AlwaysCompress always runs LZ4, even if the output is larger than the input.
        // Use Compress() with the magic-byte check for anti-expansion.
        var data = new byte[2000];
        RandomNumberGenerator.Fill(data);
        byte[] result = Compressor.AlwaysCompress(data);
        Assert.True(Compressor.IsLz4Frame(result));
    }

    /// <summary>
    /// Regression: XZ block-header size field must include the size byte in padding;
    /// large buffers (varint-heavy uSize) used to fail decompress with "index indicator not found".
    /// </summary>
    [Theory]
    [InlineData(1 * 1024 * 1024)]
    [InlineData(8 * 1024 * 1024)]
    [InlineData(32 * 1024 * 1024)]
    [InlineData(64 * 1024 * 1024)]
    public void Xz_AlwaysCompress_LargeRoundTrip(int size)
    {
        var data = new byte[size];
        new Random(42).NextBytes(data);
        for (int i = 0; i < data.Length; i += 4) data[i] = 0; // compressible
        byte[] compressed = Compressor.AlwaysCompress(data, Constants.CompressionXz);
        Assert.True(compressed.Length >= 6 && compressed[0] == 0xFD && compressed[1] == 0x37,
            "expected XZ magic");
        byte[] round = Compressor.Decompress(compressed, Constants.CompressionXz);
        Assert.Equal(data, round);
    }

    [Fact]
    public void IsLz4Frame_DetectsLz4Magic()
    {
        // LZ4 frame magic bytes: 0x04 0x22 0x4D 0x18
        var lz4Frame = new byte[] { 0x04, 0x22, 0x4D, 0x18, 0x60, 0x00, 0x00, 0x00 };
        Assert.True(Compressor.IsLz4Frame(lz4Frame));
        Assert.False(Compressor.IsLz4Frame(new byte[] { 0x00, 0x00, 0x00, 0x00 }));
    }

    // -- ZstdAlgorithm tests --

    [Fact]
    public void ZstdAlgorithm_RoundTrip()
    {
        var algo = new ZstdAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = algo.Compress(data);
        Assert.True(algo.CanHandle(compressed));
        byte[] decompressed = algo.Decompress(compressed);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void ZstdAlgorithm_CanHandle_DetectsMagic()
    {
        var algo = new ZstdAlgorithm();
        byte[] compressed = algo.Compress(new byte[100]);
        Assert.True(algo.CanHandle(compressed));
        Assert.False(algo.CanHandle(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
        Assert.False(algo.CanHandle(Array.Empty<byte>()));
    }

    [Fact]
    public void ZstdAlgorithm_Level_DifferentOptions_ProduceValidData()
    {
        var algo = new ZstdAlgorithm();
        var data = new byte[200_000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);

        byte[] fastCompressed = algo.Compress(data, "1");
        byte[] bestCompressed = algo.Compress(data, "19");

        Assert.Equal(data, algo.Decompress(fastCompressed));
        Assert.Equal(data, algo.Decompress(bestCompressed));
    }

    [Fact]
    public void ZstdAlgorithm_NullOptions_UsesDefaultLevel()
    {
        var algo = new ZstdAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = algo.Compress(data);
        byte[] decompressed = algo.Decompress(compressed);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void ZstdAlgorithm_InvalidOptions_UsesDefault()
    {
        var algo = new ZstdAlgorithm();
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 256);
        byte[] compressed = algo.Compress(data, "not-a-number");
        byte[] decompressed = algo.Decompress(compressed);
        Assert.Equal(data, decompressed);
    }

    [Fact]
    public void ZstdAlgorithm_CompressViaRouter()
    {
        var router = new CompressionRouter();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] result = router.Compress(data, Constants.CompressionZstd);
        Assert.True(result.Length > 0);
        Assert.True(new ZstdAlgorithm().CanHandle(result));
        byte[] back = router.Decompress(result, Constants.CompressionZstd);
        Assert.Equal(data, back);
    }

    // -- Lz4Algorithm level option tests --

    [Fact]
    public void Lz4Algorithm_Level_SmallOption()
    {
        var algo = new Lz4Algorithm();
        var data = new byte[50_000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] compressed = algo.Compress(data, "0");
        Assert.True(algo.CanHandle(compressed));
        Assert.Equal(data, algo.Decompress(compressed));
    }

    [Fact]
    public void Lz4Algorithm_NullOptions_DefaultsToFast()
    {
        var algo = new Lz4Algorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i % 256);
        byte[] compressed = algo.Compress(data);
        Assert.True(algo.CanHandle(compressed));
        Assert.Equal(data, algo.Decompress(compressed));
    }

    [Fact]
    public void CompressionRouter_ZstdOptions_ArePassed()
    {
        var router = new CompressionRouter();
        var data = new byte[200_000];
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(i & 0xFF);
        byte[] fastCompressed = router.Compress(data, Constants.CompressionZstd, "1");
        byte[] bestCompressed = router.Compress(data, Constants.CompressionZstd, "19");
        Assert.Equal(data, router.Decompress(fastCompressed, Constants.CompressionZstd));
        Assert.Equal(data, router.Decompress(bestCompressed, Constants.CompressionZstd));
    }

    [Fact]
    public void GzipAlgorithm_RoundTrip()
    {
        var algo = new GzipAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.True(algo.CanHandle(c));
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void BrotliAlgorithm_RoundTrip()
    {
        var algo = new BrotliAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void LzmaAlgorithm_RoundTrip()
    {
        var algo = new LzmaAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void LzoAlgorithm_RoundTrip()
    {
        var algo = new LzoAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void Lz4HcAlgorithm_RoundTrip()
    {
        var algo = new Lz4HcAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.True(algo.CanHandle(c));
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void XpressHuffAlgorithm_RoundTrip()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var algo = new XpressHuffAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void LzmsAlgorithm_RoundTrip()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        var algo = new LzmsAlgorithm();
        var data = new byte[5000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i & 0xFF);
        byte[] c = algo.Compress(data);
        Assert.Equal(data, algo.Decompress(c));
    }

    [Fact]
    public void AllAlgorithms_RouterDispatch()
    {
        var router = new CompressionRouter();
        var data = new byte[2000];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);
        var methods = new List<string> { Constants.CompressionGzip, Constants.CompressionBrotli,
            Constants.CompressionLzma, Constants.CompressionLzo, Constants.CompressionLz4Hc };
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            methods.Add(Constants.CompressionXpressHuff);
            methods.Add(Constants.CompressionLzms);
        }
        foreach (var m in methods)
        {
            byte[] c = router.Compress(data, m);
            Assert.True(c.Length > 0, $"{m}: compress returned empty");
            byte[] d = router.Decompress(c, m);
            Assert.Equal(data, d);
        }
    }

    [Fact]
    public void TansTable_LiteralOnly_RoundTrip()
    {
        int L = 1024;
        byte[] syms = { 65, 66, 67, 65, 65, 68, 65, 69, 70, 65 };
        var freq = new int[256];
        for (int i = 0; i < 256; i++) freq[i] = 1;
        foreach (byte b in syms) freq[b] += 10;

        var table = TansTable.Build(freq, L);

        // Encode in REVERSE -- bits: q-1 per token (11 bits LSB-first), state at end
        var bits = new List<byte>();
        int es = L;
        for (int i = syms.Length - 1; i >= 0; i--)
        {
            var (next, q) = table.Encode(es, syms[i]);
            int v = q - 1;
            for (int j = 10; j >= 0; j--) bits.Add((byte)((v >> j) & 1));
            es = next;
        }

        // Store final state as 16 bits LSB-first at end, then REVERSE entire list
        for (int i = 0; i < 16; i++) bits.Add((byte)((es >> i) & 1));
        bits.Reverse();

        // Decoder reads state MSB-first from front, then tokens from end backward
        // But since list is reversed: state at front, tokens follow reversed
        int pos = 0;
        int RB() => pos < bits.Count ? bits[pos++] : 0;
        int ds = 0;
        for (int i = 0; i < 16; i++) ds |= RB() << (15 - i);

        var results = new byte[syms.Length];
        for (int ti = 0; ti < syms.Length; ti++)
        {
            int sym = table.GetSymbol(ds);
            // Read 11 bits for q-1, LSB-first
            int v = 0;
            for (int j = 0; j < 11; j++) v |= RB() << j;
            int q = v + 1;
            bool found = table.TryDecode(ds, q, out ds);
            results[ti] = found ? (byte)sym : (byte)0;
        }

        Assert.Equal(syms, results);
    }

    [Fact]
    public void Ckc_RoundTrip_Small()
    {
        var data = "Hello World! This is a test string for CKC compression. Repeat: Hello World! Hello World!"u8.ToArray();
        var algo = new CkcAlgorithm();
        byte[] c = algo.Compress(data);
        byte[] d = algo.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_RoundTrip_LargeRepeating()
    {
        var data = new byte[65536];
        new Random(42).NextBytes(data);
        for (int i = 0; i < 4096; i++)
            Buffer.BlockCopy(data, i * 8, data, i * 16, 8);
        var algo = new CkcAlgorithm();
        byte[] c = algo.Compress(data);
        byte[] d = algo.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_RoundTrip_ZeroLen()
    {
        var data = Array.Empty<byte>();
        var algo = new CkcAlgorithm();
        byte[] c = algo.Compress(data);
        byte[] d = algo.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_CanHandle()
    {
        var algo = new CkcAlgorithm();
        var validHeader = new byte[] { 0x43, 0x4B, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
        Assert.True(algo.CanHandle(validHeader));
        Assert.False(algo.CanHandle(new byte[] { 0x01, 0x02, 0x03 }));
    }

    [Fact]
    public void Ckc_RouterIntegration()
    {
        var router = new CompressionRouter();
        var data = new byte[2048];
        new Random(42).NextBytes(data);
        for (int i = 0; i < 256; i++)
            Buffer.BlockCopy(data, i * 4, data, i * 8, 4);

        byte[] c = router.AlwaysCompress(data, Constants.CompressionCkc);
        byte[] d = router.Decompress(c, Constants.CompressionCkc);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_BitStream_RoundTrip()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        byte[] c = CkcEncoder.CompressSingle(data);
        byte[] d = CkcEncoder.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_LzMatch_RoundTrip()
    {
        // 5 A's followed by 5 more A's 鈥?should produce literal A + match(4,5)
        var data = new byte[] { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };
        byte[] c = CkcEncoder.CompressSingle(data);
        byte[] d = CkcEncoder.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_SingleByte_RoundTrip()
    {
        var data = new byte[] { 65 };
        byte[] c = CkcEncoder.CompressSingle(data);
        // header: CKC\1 + len=1 -- 8 bytes
        // Then: flag=0 + 65 in 8 bits (01000001)
        // Byte 0 of payload = 0x82 = flag|(65 bits 0-6)
        // Byte 1 of payload = 0x00 = 65 bit 7
        byte[] d = CkcEncoder.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void TansEncode_SingleByte_RoundTrip()
    {
        var data = new byte[] { 65 };
        byte[] c = CkcEncoder.CompressSingle(data);  // uses trained tables + freq serialization
        byte[] d = CkcEncoder.Decompress(c);         // reads freq, rebuilds tables, decodes
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_Engine_FullPipeline_RoundTrip()
    {
        var rng = new Random(42);
        var fragments = new List<byte[]>();
        var original = new List<byte>();
        var vocab = new byte[] { 
            116,104,101,32,113,117,105,99,107,32,98,114,111,119,110,32,102,111,120, // "the quick brown fox"
            106,117,109,112,115,32,111,118,101,114,32,116,104,101,32,108,97,122,121,32, // "jumps over the lazy "
            100,111,103,32,84,72,69,32,81,85,73,67,75,32,66,82,79,87,78,32, // "dog THE QUICK BROWN "
            70,79,88,32,74,85,77,80,83,32,79,86,69,82, // "FOX JUMPS OVER"
        };
        for (int f = 0; f < 15; f++)
        {
            int fragLen = 3000 + rng.Next(2000);
            var frag = new byte[fragLen];
            for (int i = 0; i < fragLen; i++)
            {
                if (i >= 32 && rng.Next(5) == 0)
                    frag[i] = frag[i - rng.Next(1, 32)];
                else
                    frag[i] = vocab[rng.Next(vocab.Length)];
            }
            fragments.Add(frag);
            original.AddRange(frag);
        }

        CkcEngine.CompressInPlace(fragments);
        CkcEngine.DecompressInPlace(fragments);

        var result = new byte[original.Count];
        int off = 0;
        for (int i = 0; i < fragments.Count; i++)
        {
            Array.Copy(fragments[i], 0, result, off, fragments[i].Length);
            off += fragments[i].Length;
        }
        Assert.Equal(original.ToArray(), result);
    }

    [Fact]
    public void Ckc_Benchmark_DiverseDatasets()
    {
        var rng = new Random(42);
        var results = new System.Text.StringBuilder();
        results.AppendLine("Dataset | Raw(KB) | CKC(KB) | Ratio% | Bk(ms) | Rs(ms) | SHA");

        void Run(string name, byte[] data, int fragCount)
        {
            int fragSize = data.Length / fragCount;
            var fragments = new List<byte[]>();
            for (int i = 0; i < fragCount; i++)
            {
                int start = i * fragSize;
                int end = (i == fragCount - 1) ? data.Length : start + fragSize;
                var frag = new byte[end - start];
                Array.Copy(data, start, frag, 0, frag.Length);
                fragments.Add(frag);
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            CkcEngine.CompressInPlace(fragments);
            long bk = sw.ElapsedMilliseconds;

            long disk = 0;
            foreach (var f in fragments) disk += f.Length;

            sw.Restart();
            CkcEngine.DecompressInPlace(fragments);
            long rs = sw.ElapsedMilliseconds;

            var roundtrip = new byte[data.Length];
            int off = 0;
            foreach (var f in fragments) { Array.Copy(f, 0, roundtrip, off, f.Length); off += f.Length; }
            string sha = SHA256.HashData(roundtrip).SequenceEqual(SHA256.HashData(data)) ? "PASS" : "FAIL";

            results.AppendLine(
                $"{name} | {data.Length/1024} | {disk/1024} | {100.0*disk/data.Length:F1} | {bk} | {rs} | {sha}");
        }

        // Dataset 1: source code (repeated Ckc source files)
        var srcDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "src", "RDRF.Core", "Compression", "Ckc");
        var csFiles = Directory.Exists(srcDir)
            ? Directory.GetFiles(srcDir, "*.cs").SelectMany(f => File.ReadAllBytes(f)).ToArray()
            : Encoding.UTF8.GetBytes(new string('x', 50000));
        var srcData = new byte[csFiles.Length * 4]; // repeat 4x for better benchmark
        for (int k = 0; k < 4; k++) Array.Copy(csFiles, 0, srcData, k * csFiles.Length, csFiles.Length);
        Run("CkcSource4x", srcData, 8);

        // Dataset 2: binary DLL
        var dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RDRF.Core.dll");
        var dllData = File.Exists(dllPath) ? File.ReadAllBytes(dllPath) : new byte[200000];
        Run("Dll", dllData, 4);

        // Dataset 3: random data (incompressible)
        var randomData = new byte[200_000];
        rng.NextBytes(randomData);
        Run("Random", randomData, 4);

        // Dataset 4: highly redundant text
        var repeatText = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n", 5000)));
        Run("RepeatText", repeatText, 8);

        // Dataset 5: partial redundancy (mixed text + random noise)
        var mixed = new byte[200_000];
        var textPart = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("Hello World! This is a pattern that repeats. ", 3000)));
        textPart.CopyTo(mixed, 0);
        rng.NextBytes(new Span<byte>(mixed, textPart.Length, mixed.Length - textPart.Length));
        Run("Mixed50", mixed, 6);

        // Also test with zstd for comparison
        foreach (var (name, data, fc) in new (string, byte[], int)[] {
            ("Zstd_Src", srcData, 8), ("Zstd_Dll", dllData, 4), ("Zstd_Rnd", randomData, 4),
            ("Zstd_Txt", repeatText, 8), ("Zstd_Mix", mixed, 6)
        })
        {
            var swZ = System.Diagnostics.Stopwatch.StartNew();
            var comp = Compressor.Compress(data, "zstd");
            long bkZ = swZ.ElapsedMilliseconds;
            swZ.Restart();
            var decomp = Compressor.Decompress(comp, "zstd");
            long rsZ = swZ.ElapsedMilliseconds;
            string shaZ = SHA256.HashData(decomp).SequenceEqual(SHA256.HashData(data)) ? "PASS" : "FAIL";
            results.AppendLine(
                $"{name} | {data.Length/1024} | {comp.Length/1024} | {100.0*comp.Length/data.Length:F1} | {bkZ} | {rsZ} | {shaZ}");
        }

        // Also test with LZ4 for comparison
        foreach (var (name, data, fc) in new (string, byte[], int)[] {
            ("LZ4_Src", srcData, 8), ("LZ4_Dll", dllData, 4), ("LZ4_Rnd", randomData, 4),
            ("LZ4_Txt", repeatText, 8), ("LZ4_Mix", mixed, 6)
        })
        {
            var swL = System.Diagnostics.Stopwatch.StartNew();
            var comp = Compressor.Compress(data, "lz4");
            long bkL = swL.ElapsedMilliseconds;
            swL.Restart();
            var decomp = Compressor.Decompress(comp, "lz4");
            long rsL = swL.ElapsedMilliseconds;
            string shaL = SHA256.HashData(decomp).SequenceEqual(SHA256.HashData(data)) ? "PASS" : "FAIL";
            results.AppendLine(
                $"{name} | {data.Length/1024} | {comp.Length/1024} | {100.0*comp.Length/data.Length:F1} | {bkL} | {rsL} | {shaL}");
        }

        _output?.WriteLine(results.ToString());
        Assert.DoesNotContain("FAIL", results.ToString());
    }

    [Fact(Skip = "BWT experimental, Inverse rotation offset requires further debug")]
    public void Ckc_Bwt_RoundTrip()
    {
        var data = "Hello World! This is a test string. Hello World! This is a test string."u8.ToArray();
        byte[] c = CkcEncoder.CompressSingle(data, "bwt");
        byte[] d = CkcEncoder.DecompressSingle(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_Delta_RoundTrip()
    {
        var data = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog."u8.ToArray();
        var algo = new CkcAlgorithm();
        byte[] c = algo.Compress(data, "delta");
        byte[] d = algo.Decompress(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_Dict_RoundTrip()
    {
        var data = "public void Test() { var x = new List<int>(); return x.Count; } public void Test2() { var y = new List<int>(); return y.Count; }"u8.ToArray();
        var dict = "public void Test() { var x = new List<int>(); return x.Count; }"u8.ToArray();
        byte[] c = CkcEncoder.CompressSingleWithDict(data, dict);
        byte[] d = CkcEncoder.DecompressSingleWithDict(c);
        Assert.Equal(data, d);
    }

    [Fact]
    public void Ckc_Benchmark_Dict()
    {
        var rng = new Random(42);
        var results = new StringBuilder();
        results.AppendLine("DictDataset | Raw(KB) | CKC(KB) | Ratio% | Bk(ms) | Rs(ms) | SHA");

        void Run(string name, byte[] data, byte[] dict, int fragCount)
        {
            int fragSize = data.Length / fragCount;
            var fragments = new List<byte[]>();
            for (int i = 0; i < fragCount; i++)
            {
                int start = i * fragSize;
                int end = (i == fragCount - 1) ? data.Length : start + fragSize;
                var frag = new byte[end - start];
                Array.Copy(data, start, frag, 0, frag.Length);
                fragments.Add(frag);
            }

            var sw = System.Diagnostics.Stopwatch.StartNew();
            CkcEngine.CompressInPlace(fragments, false, dict);
            long bk = sw.ElapsedMilliseconds;
            long disk = 0; foreach (var frag in fragments) disk += frag.Length;

            sw.Restart();
            CkcEngine.DecompressInPlace(fragments);
            long rs = sw.ElapsedMilliseconds;
            var roundtrip = new byte[data.Length]; int off = 0;
            foreach (var frag in fragments) { Array.Copy(frag, 0, roundtrip, off, frag.Length); off += frag.Length; }
            string sha = SHA256.HashData(roundtrip).SequenceEqual(SHA256.HashData(data)) ? "PASS" : "FAIL";
            results.AppendLine($"{name} | {data.Length/1024} | {disk/1024} | {100.0*disk/data.Length:F1} | {bk} | {rs} | {sha}");
        }

        // Train a dict from the first 4KB of source code files
        var srcDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", "..", "src", "RDRF.Core", "Compression", "Ckc");
        byte[] allCkcSources = Array.Empty<byte>();
        if (Directory.Exists(srcDir))
            allCkcSources = Directory.GetFiles(srcDir, "*.cs").SelectMany(f => File.ReadAllBytes(f)).ToArray();
        if (allCkcSources.Length < 1024) allCkcSources = Encoding.UTF8.GetBytes(new string('x', 1024));
        var trainSample = new byte[Math.Min(16384, allCkcSources.Length)];
        Array.Copy(allCkcSources, trainSample, trainSample.Length);
        var dict = CkcDictionary.Train(new[] { trainSample }, 4096);

        // Repeat source data 4x for benchmark
        var srcData = new byte[allCkcSources.Length * 4];
        for (int k = 0; k < 4; k++) Array.Copy(allCkcSources, 0, srcData, k * allCkcSources.Length, allCkcSources.Length);
        Run("SrcDict", srcData, dict, 8);

        var dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "RDRF.Core.dll");
        var dllData = File.Exists(dllPath) ? File.ReadAllBytes(dllPath) : new byte[200000];
        Run("DllDict", dllData, dict, 4);

        _output?.WriteLine(results.ToString());
        Assert.DoesNotContain("FAIL", results.ToString());
    }
}
