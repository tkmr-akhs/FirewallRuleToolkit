using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ServiceValueParserTests
{
    [Fact]
    public void ParseReference_WhenAnyIsLowercase_ReturnsBuiltInAny()
    {
        var parsed = ServiceValueParser.ParseReference("any");

        Assert.Equal("0-255", parsed.Protocol);
        Assert.Equal("0-65535", parsed.SourcePort);
        Assert.Equal("0-65535", parsed.DestinationPort);
        Assert.Null(parsed.Kind);
    }

    [Fact]
    public void ParseReference_WhenAnyCaseDiffers_ReturnsKindSentinel()
    {
        var parsed = ServiceValueParser.ParseReference("ANY");

        Assert.Equal("255", parsed.Protocol);
        Assert.Equal("0", parsed.SourcePort);
        Assert.Equal("0", parsed.DestinationPort);
        Assert.Equal("ANY", parsed.Kind);
    }

    [Fact]
    public void ParseReference_WhenAxisAnyCaseDiffers_ReturnsKindSentinel()
    {
        var parsed = ServiceValueParser.ParseReference("TCP ANY 80");

        Assert.Equal("255", parsed.Protocol);
        Assert.Equal("0", parsed.SourcePort);
        Assert.Equal("0", parsed.DestinationPort);
        Assert.Equal("TCP ANY 80", parsed.Kind);
    }

    [Fact]
    public void NormalizeDefinition_WhenAxisAnyCaseDiffers_ThrowsFormatException()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-upper-any",
            Protocol = "ANY",
            SourcePort = "any",
            DestinationPort = "any",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.NormalizeDefinition(serviceDefinition));
    }
}
