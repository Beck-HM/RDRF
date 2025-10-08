using System.Security.Cryptography;
using RDRF.Core.Dssa;
using Xunit;
using Xunit.Abstractions;

namespace RDRF.Core.Tests;

public class StorageApiTests
{
    private readonly ITestOutputHelper _output;

    public StorageApiTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void ManagementFile_RecordAndLookup()
    {
        using var dir = new TempDir();
        var mgmt = new ManagementFile(dir.Path);

        mgmt.RecordFragment("fp1", 1, 0, "backendA", "path_v1_0.rdrf", 1024);
        mgmt.RecordFragment("fp1", 1, 1, "backendB", "path_v1_1.rdrf", 2048);
        mgmt.RecordRc("fp1", 1, "backendA", "rc_v1.rdrc", 512);

        var results = mgmt.Lookup("fp1", 1);
        Assert.Equal(3, results.Count);
        Assert.Contains(results, r => r.FragmentIndex == 0 && r.BackendName == "backendA");
        Assert.Contains(results, r => r.FragmentIndex == 1 && r.BackendName == "backendB");
        Assert.Contains(results, r => r.ContentType == "rc");

        _output.WriteLine("ManagementFile: Record + Lookup OK");
    }

    [Fact]
    public void ManagementFile_LookupSingle()
    {
        using var dir = new TempDir();
        var mgmt = new ManagementFile(dir.Path);

        mgmt.RecordFragment("fp1", 1, 0, "backendA", "p0.rdrf", 100);
        mgmt.RecordFragment("fp1", 1, 1, "backendB", "p1.rdrf", 200);

        var r0 = mgmt.LookupSingle("fp1", 1, 0);
        Assert.NotNull(r0);
        Assert.Equal("backendA", r0.BackendName);

        var missing = mgmt.LookupSingle("fp1", 1, 5);
        Assert.Null(missing);

        _output.WriteLine("ManagementFile: LookupSingle OK");
    }

    [Fact]
    public void ManagementFile_DeleteVersion()
    {
        using var dir = new TempDir();
        var mgmt = new ManagementFile(dir.Path);

        mgmt.RecordFragment("fp1", 1, 0, "b1", "p0.rdrf", 100);
        mgmt.RecordFragment("fp1", 2, 0, "b1", "p0_v2.rdrf", 100);

        Assert.Equal(2, mgmt.GetVersionNumbers("fp1").Count);

        mgmt.DeleteVersion("fp1", 1);

        var remaining = mgmt.GetVersionNumbers("fp1");
        Assert.Single(remaining);
        Assert.Equal(2, remaining[0]);

        _output.WriteLine("ManagementFile: DeleteVersion OK");
    }

    [Fact]
    public void ManagementFile_MultipleFingerprints()
    {
        using var dir = new TempDir();
        var mgmt = new ManagementFile(dir.Path);

        mgmt.RecordFragment("projA", 1, 0, "b1", "a_v1_0.rdrf", 100);
        mgmt.RecordFragment("projB", 1, 0, "b2", "b_v1_0.rdrf", 200);

        Assert.Single(mgmt.Lookup("projA", 1));
        Assert.Single(mgmt.Lookup("projB", 1));

        _output.WriteLine("ManagementFile: Multiple fingerprints OK");
    }

    [Theory]
    [InlineData(10, 3, new[] { 4, 3, 3 })]
    [InlineData(9, 3, new[] { 3, 3, 3 })]
    [InlineData(11, 3, new[] { 4, 4, 3 })]
    [InlineData(5, 2, new[] { 3, 2 })]
    public void Distribution_Average(int total, int backendCount, int[] expected)
    {
        var actual = new int[backendCount];
        for (int i = 0; i < total; i++)
        {
            int idx = i % backendCount;
            actual[idx]++;
        }

        for (int i = 0; i < backendCount; i++)
            Assert.Equal(expected[i], actual[i]);

        _output.WriteLine($"Distribution {total}/{backendCount}: " +
            string.Join(", ", actual));
    }

    [Fact]
    public async Task Orchestrator_WriteFragment_UsesAllBackends()
    {
        var recorder = new BackendCallRecorder();
        var orch = new StorageOrchestrator();
        orch.RegisterBackend("A", new RecordableBackend("A", recorder));
        orch.RegisterBackend("B", new RecordableBackend("B", recorder));
        orch.RegisterBackend("C", new RecordableBackend("C", recorder));

        var data = new byte[] { 1, 2, 3 };

        for (int i = 0; i < 6; i++)
        {
            var opt = new StorageUploadOptions
            {
                Fingerprint = "fp1",
                FileType = "fragment",
                FileSize = data.Length,
                FragmentCount = 6,
                FragmentIndex = i,
            };
            await orch.WriteFragmentAsync(data, opt);
        }

        Assert.Equal(6, recorder.Calls.Count);
        Assert.Contains(recorder.Calls, c => c.Contains("_0.rdrf") && c.StartsWith("A/"));
        Assert.Contains(recorder.Calls, c => c.Contains("_1.rdrf") && c.StartsWith("B/"));
        Assert.Contains(recorder.Calls, c => c.Contains("_2.rdrf") && c.StartsWith("C/"));
        _output.WriteLine($"Calls: {string.Join(", ", recorder.Calls)}");
    }

    [Fact]
    public async Task Orchestrator_WriteWithForceBackend()
    {
        var recorder = new BackendCallRecorder();
        var orch = new StorageOrchestrator();
        orch.RegisterBackend("A", new RecordableBackend("A", recorder));
        orch.RegisterBackend("B", new RecordableBackend("B", recorder));

        var opt = new StorageUploadOptions
        {
            Fingerprint = "fp1",
            FileType = "fragment",
            FileSize = 10,
            FragmentCount = 1,
            FragmentIndex = 0,
            ForceBackend = "B",
        };
        await orch.WriteFragmentAsync(new byte[] { 1 }, opt);

        Assert.Contains(recorder.Calls, c => c.StartsWith("B/"));
        _output.WriteLine("ForceBackend: OK");
    }

    private class BackendCallRecorder
    {
        public List<string> Calls { get; } = new();
        public void Record(string backend, string path) => Calls.Add($"{backend}/{path}");
    }

    private class RecordableBackend : IStorageBackend
    {
        public string Name { get; }
        private readonly BackendCallRecorder _recorder;

        public RecordableBackend(string name, BackendCallRecorder recorder)
        {
            Name = name;
            _recorder = recorder;
        }

        public Task<Stream> OpenWriteAsync(string path, long fileSize,
            IProgress<StorageProgress>? progress = null)
        {
            _recorder.Record(Name, path);
            return Task.FromResult<Stream>(new MemoryStream());
        }

        public Task<Stream> OpenReadAsync(string path)
            => Task.FromResult<Stream>(new MemoryStream());

        public Task DeleteAsync(string path) => Task.CompletedTask;
        public Task<bool> ExistsAsync(string path) => Task.FromResult(true);
        public Task<bool> PingAsync() => Task.FromResult(true);
    }

    private class TempDir : IDisposable
    {
        public string Path { get; } =
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"rdrf_test_{Guid.NewGuid():N}");
        public TempDir() => Directory.CreateDirectory(Path);
        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { }
        }
    }
}
