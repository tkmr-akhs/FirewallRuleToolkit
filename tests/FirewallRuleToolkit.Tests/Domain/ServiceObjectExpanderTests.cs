using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ServiceObjectExpanderTests
{
    [Fact]
    public void Expand_WhenRangesAreBelowThreshold_SplitsEachAxis()
    {
        var expanded = ServiceObjectExpander.Expand(
            [
                new ServiceObject
                {
                    Name = "svc",
                    Protocol = "6-7",
                    SourcePort = "1000-1001",
                    DestinationPort = "80",
                    Kind = "service"
                }
            ],
            threshold: 3).ToArray();

        Assert.Equal(4, expanded.Length);
        Assert.Contains(expanded, static value =>
            value.ProtocolStart == 6
            && value.ProtocolFinish == 6
            && value.SourcePortStart == 1000
            && value.SourcePortFinish == 1000
            && value.DestinationPortStart == 80
            && value.DestinationPortFinish == 80
            && value.Kind == "service");
        Assert.Contains(expanded, static value =>
            value.ProtocolStart == 7
            && value.ProtocolFinish == 7
            && value.SourcePortStart == 1001
            && value.SourcePortFinish == 1001
            && value.DestinationPortStart == 80
            && value.DestinationPortFinish == 80
            && value.Kind == "service");
    }
}
