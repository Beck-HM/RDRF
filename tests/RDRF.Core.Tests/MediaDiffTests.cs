using System.Drawing;
using System.Drawing.Imaging;
using RDRF.Core.Diff;
using RDRF.Core.Diff.Strategies;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

public class MediaDiffTests
{
    private readonly ITestOutputHelper _output;
    public MediaDiffTests(ITestOutputHelper output) => _output = output;

    // ── ImageDiffStrategy ──

    [Fact]
    public void Image_MatchScore_Extensions()
    {
        var s = new ImageDiffStrategy();
        Assert.Equal(1.0, s.MatchScore("photo.png", []));
        Assert.Equal(1.0, s.MatchScore("photo.jpg", []));
        Assert.Equal(1.0, s.MatchScore("photo.jpeg", []));
        Assert.Equal(1.0, s.MatchScore("photo.gif", []));
        Assert.Equal(1.0, s.MatchScore("photo.bmp", []));
        Assert.Equal(1.0, s.MatchScore("photo.webp", []));
        Assert.Equal(1.0, s.MatchScore("photo.ico", []));
    }

    [Fact]
    public void Image_MatchScore_MagicBytes()
    {
        var s = new ImageDiffStrategy();
        double score = s.MatchScore(null, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        Assert.Equal(0.95, score);

        score = s.MatchScore(null, [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00]);
        Assert.Equal(0.95, score);

        score = s.MatchScore(null, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x00, 0x00]);
        Assert.Equal(0.95, score);
    }

    [Fact]
    public void Image_MatchScore_NonImage()
    {
        var s = new ImageDiffStrategy();
        Assert.Equal(0, s.MatchScore("file.txt", "hello"u8));
    }

    [Fact]
    public void Image_ComputeDiff_SizeChange()
    {
        var s = new ImageDiffStrategy();
        var oldImg = new Bitmap(1, 1);
        var newImg = new Bitmap(2, 2);
        byte[] oldBytes = ImgToBytes(oldImg, ImageFormat.Png);
        byte[] newBytes = ImgToBytes(newImg, ImageFormat.Png);

        var result = s.ComputeDiff(oldBytes, newBytes, "test.png");

        Assert.Contains("1x1", result.HumanDiff);
        Assert.Contains("2x2", result.HumanDiff);
        _output.WriteLine($"Image diff:\n{result.HumanDiff}");
    }

    [Fact]
    public void Image_ComputeDiff_FormatChange()
    {
        var s = new ImageDiffStrategy();
        var img = new Bitmap(10, 10);
        byte[] pngBytes = ImgToBytes(img, ImageFormat.Png);
        byte[] bmpBytes = ImgToBytes(new Bitmap(10, 10), ImageFormat.Bmp);

        var result = s.ComputeDiff(pngBytes, bmpBytes, "test");

        Assert.Contains("png", result.HumanDiff.ToLowerInvariant());
        Assert.Contains("bmp", result.HumanDiff.ToLowerInvariant());
    }

    // ── MediaDiffStrategy ──

    [Fact]
    public void Media_MatchScore_AudioExtensions()
    {
        var s = new MediaDiffStrategy();
        Assert.Equal(1.0, s.MatchScore("song.mp3", []));
        Assert.Equal(1.0, s.MatchScore("song.flac", []));
        Assert.Equal(1.0, s.MatchScore("song.wav", []));
        Assert.Equal(1.0, s.MatchScore("song.ogg", []));
        Assert.Equal(1.0, s.MatchScore("song.m4a", []));
    }

    [Fact]
    public void Media_MatchScore_VideoExtensions()
    {
        var s = new MediaDiffStrategy();
        Assert.Equal(1.0, s.MatchScore("video.mp4", []));
        Assert.Equal(1.0, s.MatchScore("video.mkv", []));
        Assert.Equal(1.0, s.MatchScore("video.avi", []));
        Assert.Equal(1.0, s.MatchScore("video.mov", []));
    }

    [Fact]
    public void Media_MatchScore_NonMedia()
    {
        var s = new MediaDiffStrategy();
        Assert.Equal(0, s.MatchScore("file.txt", []));
    }

    [Fact]
    public void Media_ComputeDiff_ValidFiles_NoCrash()
    {
        var s = new MediaDiffStrategy();
        byte[] oldData = [0, 1, 2];
        byte[] newData = [0, 1, 2, 3];

        var result = s.ComputeDiff(oldData, newData, "test.mp3");

        Assert.NotNull(result);
        Assert.NotNull(result.HumanDiff);
        _output.WriteLine($"Media diff for non-media content:\n{result.HumanDiff}");
    }

    [Fact]
    public void Media_ComputeDiff_Identical()
    {
        var s = new MediaDiffStrategy();
        byte[] data = [0, 1, 2, 3];

        var result = s.ComputeDiff(data, data, "same.mp3");

        Assert.Empty(result.Lines);
    }

    [Fact]
    public void DiffEngine_RoutesToCorrectStrategy()
    {
        var engine = new DiffEngine();

        // Image file
        var imgSample = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00 };
        var strategy = engine.SelectStrategy("photo.png", imgSample);
        Assert.True(strategy is ImageDiffStrategy, $"Expected ImageDiffStrategy, got {strategy.GetType().Name}");

        // Media file
        strategy = engine.SelectStrategy("song.mp3", []);
        Assert.True(strategy is MediaDiffStrategy, $"Expected MediaDiffStrategy, got {strategy.GetType().Name}");

        // JSON file
        strategy = engine.SelectStrategy("config.json", "{\"a\":1}"u8);
        Assert.True(strategy is JsonDiffStrategy, $"Expected JsonDiffStrategy, got {strategy.GetType().Name}");
    }

    private static byte[] ImgToBytes(Image img, ImageFormat fmt)
    {
        using var ms = new MemoryStream();
        img.Save(ms, fmt);
        img.Dispose();
        return ms.ToArray();
    }
}
