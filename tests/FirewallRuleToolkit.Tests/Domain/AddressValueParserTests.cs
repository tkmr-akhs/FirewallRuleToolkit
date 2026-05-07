using FirewallRuleToolkit.Domain.Services;

namespace FirewallRuleToolkit.Tests.Domain;

public sealed class AddressValueParserTests
{
    [Fact]
    public void Parse_WhenAnyIsLowercase_ReturnsFullRange()
    {
        var parsed = AddressValueParser.Parse("any");

        Assert.Equal(0u, parsed.Start);
        Assert.Equal(uint.MaxValue, parsed.Finish);
    }

    [Fact]
    public void Parse_WhenAnyCaseDiffers_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => AddressValueParser.Parse("ANY"));
    }

    [Fact]
    public void TryCreateBuiltInValue_WhenAnyCaseDiffers_ReturnsFalse()
    {
        var normalized = AddressValueParser.TryCreateBuiltInValue("ANY", out var normalizedValue);

        Assert.False(normalized);
        Assert.Equal(string.Empty, normalizedValue);
    }

    [Fact]
    public void Parse_WhenCidrHostBitsExist_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => AddressValueParser.Parse("192.168.1.10/24"));
    }

    [Fact]
    public void Parse_WhenSingleIpv4DoesNotHavePrefix_ThrowsFormatException()
    {
        var exception = Assert.Throws<FormatException>(() => AddressValueParser.Parse("192.168.1.10"));

        Assert.Contains("/32", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_WhenCidr32_ReturnsSingleAddressRange()
    {
        var parsed = AddressValueParser.Parse("192.168.1.10/32");

        Assert.Equal(0xC0A8010Au, parsed.Start);
        Assert.Equal(0xC0A8010Au, parsed.Finish);
    }
}
