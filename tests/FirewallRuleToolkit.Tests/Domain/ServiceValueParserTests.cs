using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ServiceValueParserTests
{
    [Fact]
    public void ParseObject_WhenAnyIsLowercase_ReturnsBuiltInAny()
    {
        var parsed = ServiceValueParser.ParseObject("any");

        Assert.Equal("0-255", parsed.Protocol);
        Assert.Equal("0-65535", parsed.SourcePort);
        Assert.Equal("0-65535", parsed.DestinationPort);
        Assert.Null(parsed.Kind);
    }

    [Fact]
    public void ParseObject_WhenAnyCaseDiffers_ReturnsKindSentinel()
    {
        var parsed = ServiceValueParser.ParseObject("ANY");

        Assert.Equal("255", parsed.Protocol);
        Assert.Equal("0", parsed.SourcePort);
        Assert.Equal("0", parsed.DestinationPort);
        Assert.Equal("ANY", parsed.Kind);
    }

    [Fact]
    public void ParseObject_WhenAxisAnyCaseDiffers_ReturnsKindSentinel()
    {
        var parsed = ServiceValueParser.ParseObject("TCP ANY 80");

        Assert.Equal("255", parsed.Protocol);
        Assert.Equal("0", parsed.SourcePort);
        Assert.Equal("0", parsed.DestinationPort);
        Assert.Equal("TCP ANY 80", parsed.Kind);
    }

    [Fact]
    public void NormalizeObject_WhenAxisAnyCaseDiffers_ThrowsFormatException()
    {
        var serviceObject = new ServiceObject
        {
            Name = "svc-upper-any",
            Protocol = "ANY",
            SourcePort = "any",
            DestinationPort = "any",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.NormalizeObject(serviceObject));
    }
}
