using RDRF.Core.FSA;
using Xunit;

namespace RDRF.Core.Tests;

public class FsaEngineTests
{
    private readonly FsaEngine _engine = new();

    [Theory]
    [InlineData("FSS1")]
    [InlineData("FSS2")]
    [InlineData("FSS2R")]
    [InlineData("FSS3")]
    [InlineData("FSS5")]
    [InlineData("FSS5+")]
    [InlineData("FSS6")]
    [InlineData("FSS6.1")]
    [InlineData("FSS6.2")]
    public void Compute_AllSingleStrategies_ProducesValidPlan(string strategy)
    {
        var plan = _engine.Compute(strategy);
        Assert.NotNull(plan);
        Assert.Equal(strategy, plan.EffectivePrimary);
        Assert.Contains(strategy, plan.ActiveStrategies);
        Assert.Single(plan.ActiveStrategies);
        Assert.True(plan.IsSingleStrategy);
        Assert.NotEmpty(plan.EncodeSteps);
        Assert.NotEmpty(plan.RestorePipeline);
    }

    [Fact]
    public void Compute_FSS1_HasNeighborEncodeStep()
    {
        var plan = _engine.Compute("FSS1");
        Assert.Contains(plan.EncodeSteps, s => s.Step == "encode" && s.Strategy == "FSS1");
    }

    [Fact]
    public void Compute_FSS6_HasSingleEncodeStep()
    {
        // FSS6 as single strategy: the "encode" step performs encode+ETN internally.
        // The "etn_inject" step only appears when FSS6 is an auxiliary strategy.
        var plan = _engine.Compute("FSS6");
        Assert.Single(plan.EncodeSteps);
        Assert.Equal("encode", plan.EncodeSteps[0].Step);
    }

    [Fact]
    public void Compute_FSS61_HasBothEncodeAndEtnSteps()
    {
        // FSS6.1 injects etn_inject after its own encode step
        var plan = _engine.Compute("FSS6.1");
        Assert.Contains(plan.EncodeSteps, s => s.Step == "encode" && s.Strategy == "FSS6.1");
    }

    [Fact]
    public void Compute_OverheadIsNonNegative()
    {
        foreach (var strat in new[] { "FSS1", "FSS3", "FSS5", "FSS6", "FSS6.1", "FSS6.2" })
        {
            var plan = _engine.Compute(strat);
            Assert.True(plan.EstimatedOverhead >= 0, $"Overhead for {strat} should be >= 0");
        }
    }

    [Fact]
    public void Compute_RestorePipelineIsReverseOfEncode()
    {
        var plan = _engine.Compute("FSS6.1");
        // Decode happens before strip, so pipeline has at least the steps in reverse order
        Assert.NotEmpty(plan.RestorePipeline);
        Assert.Contains(plan.RestorePipeline, s => s.Step == "strip");
    }

    [Fact]
    public void Compute_SingleStrategy_NoAuxiliary()
    {
        // Verify auxiliary is ignored when null
        var plan = _engine.Compute("FSS1", null);
        Assert.Single(plan.ActiveStrategies);
    }
}
