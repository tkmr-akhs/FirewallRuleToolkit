using System.Text;

namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// 文字コード オプションを <see cref="Encoding"/> として解決します。
/// </summary>
internal static class EncodingOptionResolver
{
    public static Encoding Resolve(string? encoding, bool withBom)
    {
        if (string.IsNullOrWhiteSpace(encoding) || encoding.Equals("utf-8", StringComparison.OrdinalIgnoreCase))
        {
            return new UTF8Encoding(withBom);
        }

        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(encoding);
    }
}
