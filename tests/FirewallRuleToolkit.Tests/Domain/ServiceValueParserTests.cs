using FirewallRuleToolkit.Domain.Entities;
using FirewallRuleToolkit.Domain.Services;
using FirewallRuleToolkit.Domain.ValueObjects;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class ServiceValueParserTests
{
    [Fact]
    public void TryCreateBuiltInValue_WhenAnyIsLowercase_ReturnsBuiltInAny()
    {
        var parsed = ServiceValueParser.TryCreateBuiltInValue("any", out var service);

        Assert.True(parsed);
        Assert.Equal("0-255", service.Protocol);
        Assert.Equal("0-65535", service.SourcePort);
        Assert.Equal("0-65535", service.DestinationPort);
        Assert.Null(service.Kind);
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
    public void TryParseCanonicalDirectReference_WhenCanonical_ReturnsDirectService()
    {
        var parsed = ServiceValueParser.TryParseCanonicalDirectReference("6 1-65535 80", out var service);

        Assert.True(parsed);
        Assert.Equal("6", service.Protocol);
        Assert.Equal("1-65535", service.SourcePort);
        Assert.Equal("80", service.DestinationPort);
        Assert.Null(service.Kind);
    }

    [Theory]
    [InlineData("tcp any 80")]
    [InlineData("TCP 1-65535 80")]
    [InlineData("6 any 80")]
    [InlineData("6 0 80")]
    [InlineData("6 0-1023 80")]
    [InlineData("255 1-65535 80")]
    [InlineData("0-255 1-65535 80")]
    public void TryParseCanonicalDirectReference_WhenValueIsNotCanonical_ReturnsFalse(string value)
    {
        var parsed = ServiceValueParser.TryParseCanonicalDirectReference(value, out _);

        Assert.False(parsed);
    }

    [Fact]
    public void ParseDefinition_WhenStoreValueIsCanonical_ReturnsValuesAsIs()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-web",
            Protocol = "6",
            SourcePort = "1-65535",
            DestinationPort = "80,443",
            Kind = null
        };

        var parsed = ServiceValueParser.ParseDefinition(serviceDefinition);

        Assert.Equal("6", parsed.Protocol);
        Assert.Equal("1-65535", parsed.SourcePort);
        Assert.Equal("80,443", parsed.DestinationPort);
        Assert.Null(parsed.Kind);
    }

    [Fact]
    public void ParseDefinition_WhenAxisAnyRemains_ThrowsFormatException()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-any",
            Protocol = "6",
            SourcePort = "any",
            DestinationPort = "80",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.ParseDefinition(serviceDefinition));
    }

    [Fact]
    public void ParseDefinition_WhenProtocolAliasRemains_ThrowsFormatException()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-protocol",
            Protocol = "tcp",
            SourcePort = "1-65535",
            DestinationPort = "80",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.ParseDefinition(serviceDefinition));
    }

    [Fact]
    public void ParseDefinition_WhenProtocolRangeEndsWith255_ThrowsFormatException()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-protocol-255",
            Protocol = "0-255",
            SourcePort = "1-65535",
            DestinationPort = "80",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.ParseDefinition(serviceDefinition));
    }

    [Fact]
    public void ParseDefinition_WhenPortZeroRemains_ThrowsFormatException()
    {
        var serviceDefinition = new ServiceDefinition
        {
            Name = "svc-port-zero",
            Protocol = "6",
            SourcePort = "0",
            DestinationPort = "80",
            Kind = null
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.ParseDefinition(serviceDefinition));
    }

    [Fact]
    public void Parse_WhenKindDoesNotUseSentinel_ThrowsFormatException()
    {
        var service = new ResolvedService
        {
            Protocol = "6",
            SourcePort = "1-65535",
            DestinationPort = "80",
            Kind = "application-default"
        };

        Assert.Throws<FormatException>(() => ServiceValueParser.Parse(service).ToArray());
    }
}
