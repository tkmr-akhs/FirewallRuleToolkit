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
    public void TryNormalizeBuiltInValue_WhenAnyCaseDiffers_ReturnsFalse()
    {
        var normalized = AddressValueParser.TryNormalizeBuiltInValue("ANY", out var normalizedValue);

        Assert.False(normalized);
        Assert.Equal(string.Empty, normalizedValue);
    }
}
