using FirewallRuleToolkit.Cli.OptionResolvers;

namespace FirewallRuleToolkit.Tests.Cli.OptionResolvers;

public sealed class AtomizeCommandOptionsResolverTests
{
    [Fact]
    public void ResolveThreshold_WhenThresholdIsPositive_ReturnsThreshold()
    {
        var resolved = AtomizeCommandOptionsResolver.ResolveThreshold(1, "--threshold");

        Assert.Equal(1, resolved);
    }

    [Fact]
    public void ResolveThreshold_WhenThresholdIsZero_ThrowsCommandUsageException()
    {
        var exception = Assert.Throws<FirewallRuleToolkit.Cli.CommandUsageException>(() =>
            AtomizeCommandOptionsResolver.ResolveThreshold(0, "--threshold"));

        Assert.Contains("threshold", exception.Message, StringComparison.Ordinal);
        Assert.Contains("1 以上", exception.Message, StringComparison.Ordinal);
    }
}
