using FirewallRuleToolkit.Cli.OptionResolvers;

namespace FirewallRuleToolkit.Tests.Cli.OptionResolvers;

public sealed class EncodingOptionResolverTests
{
    [Fact]
    public void Resolve_WhenEncodingIsShiftJis_ReturnsCodePage932()
    {
        var resolved = EncodingOptionResolver.Resolve("shift_jis", withBom: false);

        Assert.Equal(932, resolved.CodePage);
        Assert.Equal("許可", resolved.GetString(resolved.GetBytes("許可")));
    }

    [Fact]
    public void Resolve_WhenEncodingIsUtf8AndWithBomIsTrue_ReturnsUtf8WithBom()
    {
        var resolved = EncodingOptionResolver.Resolve("utf-8", withBom: true);

        Assert.Equal(65001, resolved.CodePage);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, resolved.GetPreamble());
    }

    [Fact]
    public void Resolve_WhenEncodingIsUtf8AndWithBomIsFalse_ReturnsUtf8WithoutBom()
    {
        var resolved = EncodingOptionResolver.Resolve("utf-8", withBom: false);

        Assert.Equal(65001, resolved.CodePage);
        Assert.Empty(resolved.GetPreamble());
    }
}
