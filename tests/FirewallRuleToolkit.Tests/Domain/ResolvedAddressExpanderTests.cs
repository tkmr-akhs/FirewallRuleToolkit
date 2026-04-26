using FirewallRuleToolkit.Domain.ValueObjects;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ResolvedAddressExpanderTests
{
    [Fact]
    public void Expand_WhenRangeIsBelowThreshold_SplitsIntoSingletons()
    {
        var expanded = ResolvedAddressExpander.Expand(
            [
                new ResolvedAddress
                {
                    Value = "192.168.1.10-192.168.1.12"
                }
            ],
            threshold: 4).ToArray();

        Assert.Collection(
            expanded,
            value =>
            {
                Assert.Equal(0xC0A8010Au, value.Start);
                Assert.Equal(0xC0A8010Au, value.Finish);
            },
            value =>
            {
                Assert.Equal(0xC0A8010Bu, value.Start);
                Assert.Equal(0xC0A8010Bu, value.Finish);
            },
            value =>
            {
                Assert.Equal(0xC0A8010Cu, value.Start);
                Assert.Equal(0xC0A8010Cu, value.Finish);
            });
    }

    [Fact]
    public void Expand_WhenCidrIsBelowThreshold_DoesNotSplitIntoSingletons()
    {
        var expanded = ResolvedAddressExpander.Expand(
            [
                new ResolvedAddress
                {
                    Value = "192.168.1.8/30"
                }
            ],
            threshold: 10).ToArray();

        var value = Assert.Single(expanded);
        Assert.Equal(0xC0A80108u, value.Start);
        Assert.Equal(0xC0A8010Bu, value.Finish);
    }
}
