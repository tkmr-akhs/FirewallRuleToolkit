namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// アドレス文字列表現を <see cref="AddressValue"/> へ変換します。
/// </summary>
public static class AddressValueParser
{
    /// <summary>
    /// アドレス文字列表現を範囲値へ変換します。
    /// </summary>
    /// <param name="value">変換対象のアドレス文字列表現。</param>
    /// <returns>変換したアドレス範囲値。</returns>
    public static AddressValue Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var trimmed = value.Trim();
        if (trimmed.Equals("any", StringComparison.Ordinal))
        {
            return new AddressValue
            {
                Start = 0u,
                Finish = uint.MaxValue
            };
        }

        if (trimmed.Contains('/', StringComparison.Ordinal))
        {
            return ParseCidr(trimmed);
        }

        if (trimmed.Contains('-', StringComparison.Ordinal))
        {
            var parts = trimmed.Split('-', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
            {
                throw new FormatException($"Unsupported address range: {trimmed}");
            }

            var start = ParseIpv4Address(parts[0]);
            var finish = ParseIpv4Address(parts[1]);
            if (start > finish)
            {
                throw new FormatException($"Address range start must be less than or equal to finish: {trimmed}");
            }

            return new AddressValue
            {
                Start = start,
                Finish = finish
            };
        }

        if (TryParseIpv4Address(trimmed, out _))
        {
            throw new FormatException($"Single IPv4 address must be expressed as CIDR /32: {trimmed}");
        }

        throw new FormatException($"Unsupported address value: {trimmed}");
    }

    /// <summary>
    /// 組み込みアドレス表現を解決済みアドレス値として解釈します。
    /// </summary>
    /// <param name="value">変換対象のアドレス文字列表現。</param>
    /// <param name="resolvedValue">解釈した解決済みアドレス値。</param>
    /// <returns>組み込みアドレス表現として解釈できた場合は <see langword="true"/>。</returns>
    public static bool TryCreateBuiltInValue(string value, out string resolvedValue)
    {
        resolvedValue = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.Trim().Equals("any", StringComparison.Ordinal))
        {
            resolvedValue = "0.0.0.0/0";
            return true;
        }

        return false;
    }

    /// <summary>
    /// CIDR 表現をアドレス範囲値へ変換します。
    /// </summary>
    /// <param name="value">CIDR 表現。</param>
    /// <returns>変換したアドレス範囲値。</returns>
    private static AddressValue ParseCidr(string value)
    {
        var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            throw new FormatException($"Unsupported CIDR value: {value}");
        }

        var address = ParseIpv4Address(parts[0]);
        if (!int.TryParse(parts[1], out var prefixLength) || prefixLength is < 0 or > 32)
        {
            throw new FormatException($"Unsupported CIDR prefix length: {value}");
        }

        var mask = CreateCidrMask(prefixLength);
        var start = address & mask;
        if (start != address)
        {
            throw new FormatException($"CIDR address must be a network address: {value}");
        }

        var finish = start | ~mask;
        return new AddressValue
        {
            Start = start,
            Finish = finish
        };
    }

    /// <summary>
    /// IPv4 アドレス表現を数値へ変換します。
    /// </summary>
    /// <param name="value">IPv4 アドレス表現。</param>
    /// <returns>IPv4 アドレスの数値表現。</returns>
    private static uint ParseIpv4Address(string value)
    {
        if (TryParseIpv4Address(value, out var address))
        {
            return address;
        }

        throw new FormatException($"Unsupported IPv4 address: {value}");
    }

    /// <summary>
    /// CIDR prefix length から IPv4 mask を作成します。
    /// </summary>
    /// <param name="prefixLength">CIDR prefix length。</param>
    /// <returns>IPv4 mask。</returns>
    private static uint CreateCidrMask(int prefixLength)
    {
        return prefixLength switch
        {
            0 => 0u,
            32 => uint.MaxValue,
            _ => uint.MaxValue << (32 - prefixLength)
        };
    }

    /// <summary>
    /// IPv4 アドレス表現を数値へ変換できるかを試行します。
    /// </summary>
    /// <param name="value">IPv4 アドレス表現。</param>
    /// <param name="address">IPv4 アドレスの数値表現。</param>
    /// <returns>IPv4 アドレス表現として解釈できた場合は <see langword="true"/>。</returns>
    private static bool TryParseIpv4Address(string value, out uint address)
    {
        address = 0;

        var octets = value.Split('.', StringSplitOptions.TrimEntries);
        if (octets.Length != 4)
        {
            return false;
        }

        for (var index = 0; index < octets.Length; index++)
        {
            if (!byte.TryParse(octets[index], out var octet))
            {
                return false;
            }

            address = (address << 8) | octet;
        }

        return true;
    }

}
