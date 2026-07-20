using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RDRF.Core.DSAA;
using RDRF.Core.Encryption;
using RDRF.Core.FragmentEngine;
using RDRF.Core.Index;
using RDRF.Server;
using Xunit;

namespace RDRF.Core.Tests;

public class ServerProtocolTests : IAsyncDisposable
{
    private readonly string _testDir;
    private readonly int _testPort;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public ServerProtocolTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"rdrf_srv_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);
        FragmentStore.StoragePath = _testDir;
        _testPort = 19800 + new Random().Next(1000);
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        try { Directory.Delete(_testDir, true); } catch { }
    }

    private async Task StartServer()
    {
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Loopback, _testPort);
        _listener.Start();
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        using (var stream = client.GetStream())
                            await ProtocolHandler.HandleAsync(stream, _cts.Token);
                    });
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        });
        await Task.Delay(200); // let server start
    }

    // --- Frame Protocol Tests ---

    [Fact]
    public void FrameRoundTrip_PutGet_Matches()
    {
        var data = Encoding.UTF8.GetBytes("Hello RDRF Protocol!");
        string name = "test_fp_0.rdrf";

        FragmentStore.WriteFragment(name, data);
        var result = FragmentStore.ReadFragment(name);
        Assert.NotNull(result);
        Assert.Equal(data, result);
    }

    [Fact]
    public void FrameRoundTrip_Delete_RemovesFile()
    {
        string name = "delete_me_0.rdrf";
        FragmentStore.WriteFragment(name, [1, 2, 3]);
        Assert.True(FragmentStore.Exists(name));
        FragmentStore.Delete(name);
        Assert.False(FragmentStore.Exists(name));
    }

    [Fact]
    public void FragmentStore_ListIndices_ReturnsSorted()
    {
        FragmentStore.WriteFragment("fp_test_3.rdrf", [3]);
        FragmentStore.WriteFragment("fp_test_1.rdrf", [1]);
        FragmentStore.WriteFragment("fp_test_10.rdrf", [10]);
        var indices = FragmentStore.ListIndices("fp_test");
        Assert.Equal([1, 3, 10], indices);
        foreach (var i in indices) FragmentStore.Delete($"fp_test_{i}.rdrf");
    }

    // --- Native Backend Integration Tests ---

    [Fact]
    public async Task Backend_PutGet_RoundTrip()
    {
        await StartServer();
        var backend = new RdrfNativeBackend("test", "127.0.0.1", _testPort);

        string path = "fp_putget_0.rdrf";
        var fragData = new byte[1024];
        new Random(42).NextBytes(fragData);

        // PUT
        await using (var ws = await backend.OpenWriteAsync(path, fragData.Length))
        {
            ws.Write(fragData, 0, fragData.Length);
        }

        // GET
        await using var rs = await backend.OpenReadAsync(path);
        var ms = new MemoryStream();
        await rs.CopyToAsync(ms);
        Assert.Equal(fragData, ms.ToArray());
    }

    [Fact]
    public async Task Backend_Exists_ReturnsCorrectly()
    {
        await StartServer();
        var backend = new RdrfNativeBackend("test", "127.0.0.1", _testPort);

        string path = "fp_exists_0.rdrf";
        Assert.False(await backend.ExistsAsync(path));

        FragmentStore.WriteFragment(path, [42]);
        Assert.True(await backend.ExistsAsync(path));

        FragmentStore.Delete(path);
        Assert.False(await backend.ExistsAsync(path));
    }

    [Fact]
    public async Task Backend_Delete_RemovesFile()
    {
        await StartServer();
        var backend = new RdrfNativeBackend("test", "127.0.0.1", _testPort);

        string path = "fp_del_0.rdrf";
        FragmentStore.WriteFragment(path, [7, 8, 9]);
        await backend.DeleteAsync(path);
        Assert.False(FragmentStore.Exists(path));
    }

    [Fact]
    public async Task Backend_Ping_ReturnsTrue()
    {
        await StartServer();
        var backend = new RdrfNativeBackend("test", "127.0.0.1", _testPort);
        Assert.True(await backend.PingAsync());
    }

    // --- Full Backup → Server → Restore Test ---

    [Fact]
    public async Task FullBackup_PushToServer_RestoreFromServer()
    {
        await StartServer();

        // Create a simple backup
        var srcDir = Path.Combine(_testDir, "src");
        var dstDir = Path.Combine(_testDir, "dst");
        Directory.CreateDirectory(srcDir);
        Directory.CreateDirectory(dstDir);

        var testFile = Path.Combine(_testDir, "testdata.bin");
        var testData = new byte[128_000];
        new Random(42).NextBytes(testData);
        File.WriteAllBytes(testFile, testData);

        byte[] password = Encoding.UTF8.GetBytes("test123");

        // Backup via RDRFEngine
        using (var engine = new RDRFEngine((byte[])password.Clone(), new LocalDSAAAdapter(srcDir)))
        {
            await engine.BackupFileAsync(testFile, "FSS1", compressionMethod: "lz4");
        }

        var idxFiles = Directory.GetFiles(srcDir, "*.indrdrf");
        Assert.NotEmpty(idxFiles);

        // Transfer to server via rdrf:// backend
        byte[] encIdx = File.ReadAllBytes(idxFiles[0]);
        (_, byte[] cbor) = RDRF.Core.Encryption.EncryptionLayer.DecryptIndexWithAutoDetect(encIdx, password);
        var index = RDRF.Core.Index.IndexManager.DeserializeIndex(cbor);
        string fp = index.CustomName ?? index.FileFingerprint;

        // Push fragments through native backend
        var backend = new RdrfNativeBackend("test-srv", "127.0.0.1", _testPort);
        var storage = new LocalDSAAAdapter(srcDir);
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fragName = FragmentEngine.Frags.FragmentFilename(fp, i);
            byte[] frag = storage.ReadFragment(fragName);
            await using var ws = await backend.OpenWriteAsync(fragName, frag.Length);
            ws.Write(frag, 0, frag.Length);
        }

        // Pull fragments back and restore
        for (int i = 0; i < index.FragmentCount; i++)
        {
            string fragName = FragmentEngine.Frags.FragmentFilename(fp, i);
            await using var rs = await backend.OpenReadAsync(fragName);
            using var ms = new MemoryStream();
            await rs.CopyToAsync(ms);
            var fragData = ms.ToArray();
            File.WriteAllBytes(Path.Combine(dstDir, fragName), fragData);
        }
        File.WriteAllBytes(Path.Combine(dstDir, fp + ".indrdrf"), encIdx);

        // Restore from dstDir
        string restoredPath = Path.Combine(_testDir, "restored.bin");
        using (var engine = new RDRFEngine((byte[])password.Clone(), new LocalDSAAAdapter(dstDir)))
        {
            bool ok = await engine.RestoreFileAsync(fp, restoredPath);
            Assert.True(ok);
        }

        // Verify
        byte[] original = File.ReadAllBytes(testFile);
        byte[] restored = File.ReadAllBytes(restoredPath);
        Assert.Equal(original, restored);
    }
}
