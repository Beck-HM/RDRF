using RDRF.Core;
using RDRF.Core.FSS;
using RDRF.Core.Index;
using Xunit;

namespace RDRF.Core.Tests;

public class RecoveryExecutorTests
{
    [Fact]
    public void ExecuteRecovery_AllFragmentsPresent_ReturnsComplete()
    {
        var fss = new FSSEngineWrapper();
        var executor = new RecoveryExecutor(fss);
        var index = new RdrfIndex
        {
            FragmentCount = 2,
            Fragments = new List<FragmentInfo>
            {
                new FragmentInfo { Index = 0, Size = 2 },
                new FragmentInfo { Index = 1, Size = 2 },
            }
        };
        var available = new Dictionary<int, byte[]>
        {
            { 0, new byte[] { 1, 2 } },
            { 1, new byte[] { 3, 4 } },
        };

        var result = executor.ExecuteRecovery(index, available);
        Assert.Equal(RecoveryStatus.Complete, result.Status);
        Assert.Equal(2, result.RecoveredFragments.Count);
    }

    [Fact]
    public void ExecuteRecovery_OneMissing_DoesNotThrow()
    {
        var fss = new FSSEngineWrapper();
        var executor = new RecoveryExecutor(fss);
        var index = new RdrfIndex
        {
            FragmentCount = 3,
            Fragments = new List<FragmentInfo>
            {
                new FragmentInfo { Index = 0, Size = 4 },
                new FragmentInfo { Index = 1, Size = 4 },
                new FragmentInfo { Index = 2, Size = 4 },
            }
        };
        var available = new Dictionary<int, byte[]>
        {
            { 0, new byte[] { 1, 2, 3, 4 } },
            { 1, new byte[] { 5, 6, 7, 8 } },
        };

        var ex = Record.Exception(() => executor.ExecuteRecovery(index, available));
        Assert.Null(ex);
    }

    [Fact]
    public void ExecuteRecovery_InvalidIndex_Throws()
    {
        var fss = new FSSEngineWrapper();
        var executor = new RecoveryExecutor(fss);

        Assert.Throws<NullReferenceException>(() =>
            executor.ExecuteRecovery(null!, new Dictionary<int, byte[]>()));
    }

    [Fact]
    public void ExecuteRecovery_NullMetadata_DoesNotThrow()
    {
        var fss = new FSSEngineWrapper();
        var executor = new RecoveryExecutor(fss);
        var index = new RdrfIndex
        {
            FragmentCount = 1,
            Fragments = new List<FragmentInfo> { new FragmentInfo { Index = 0 } }
        };
        var available = new Dictionary<int, byte[]> { { 0, new byte[] { 1 } } };

        var ex = Record.Exception(() => executor.ExecuteRecovery(index, available, metadata: null));
        Assert.Null(ex);
    }

    [Fact]
    public async Task ExecuteRecoveryAsync_MatchesSyncResult()
    {
        var fss = new FSSEngineWrapper();
        var executor = new RecoveryExecutor(fss);
        var index = new RdrfIndex
        {
            FragmentCount = 2,
            Fragments = new List<FragmentInfo>
            {
                new FragmentInfo { Index = 0, Size = 2 },
                new FragmentInfo { Index = 1, Size = 2 },
            }
        };
        var available = new Dictionary<int, byte[]>
        {
            { 0, new byte[] { 1, 2 } },
            { 1, new byte[] { 3, 4 } },
        };

        var syncResult = executor.ExecuteRecovery(index, available);
        var asyncResult = await executor.ExecuteRecoveryAsync(index, available);

        Assert.Equal(syncResult.Status, asyncResult.Status);
        Assert.Equal(syncResult.RecoveredFragments.Count, asyncResult.RecoveredFragments.Count);
    }
}
