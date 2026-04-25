using FirewallRuleToolkit.Cli.OptionResolvers;

namespace FirewallRuleToolkit.Tests.Cli.OptionResolvers;

public sealed class MergeCommandOptionsResolverTests
{
    [Fact]
    public void Resolve_WhenWkPortAndThresholdAreProvided_ReturnsNormalizedPorts()
    {
        var resolved = MergeCommandOptionsResolver.Resolve(
            "443,80,443",
            3,
            85,
            "--hspercent");

        Assert.Equal((uint)85, resolved.HsPercent);
        Assert.Equal((uint)3, resolved.WkpThreshold);
        Assert.Equal("80,443", resolved.WkPortLogValue);
        Assert.Equal([80u, 443u], resolved.WellKnownDestinationPorts.OrderBy(static port => port).ToArray());
    }

    [Fact]
    public void Resolve_WhenHsPercentIsOutOfRange_ThrowsCommandUsageException()
    {
        var exception = Assert.Throws<FirewallRuleToolkit.Cli.CommandUsageException>(() => MergeCommandOptionsResolver.Resolve(
            null,
            null,
            0,
            "--hspercent"));

        Assert.Contains("1 から 100", exception.Message, StringComparison.Ordinal);
    }
}
