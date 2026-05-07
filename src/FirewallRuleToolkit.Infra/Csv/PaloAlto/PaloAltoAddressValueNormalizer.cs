namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// Palo Alto CSV のアドレス表記を Domain が解釈できる canonical 表記へ変換します。
/// </summary>
internal static class PaloAltoAddressValueNormalizer
{
    /// <summary>
    /// 名前付きアドレス定義の値を canonical 表記へ正規化します。
    /// </summary>
    /// <param name="value">Palo Alto CSV のアドレス値。</param>
    /// <returns>canonical アドレス値。</returns>
    public static string NormalizeDefinitionValue(string value)
    {
        if (TryNormalizeAddressValue(value, out var normalizedValue))
        {
            return normalizedValue;
        }

        throw new FormatException($"Unsupported address value: {value}");
    }

    /// <summary>
    /// ポリシー参照欄の直接アドレス値だけを canonical 表記へ正規化します。
    /// </summary>
    /// <param name="value">Palo Alto CSV のアドレス参照。</param>
    /// <returns>正規化できた直接アドレス値、または元の参照名。</returns>
    public static string NormalizePolicyReference(string value)
    {
        return TryNormalizeAddressValue(value, out var normalizedValue)
            ? normalizedValue
            : value.Trim();
    }

    private static bool TryNormalizeAddressValue(string value, out string normalizedValue)
    {
        normalizedValue = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (TryParseCidr(trimmed, out var cidrAddress, out var prefixLength))
        {
            var mask = CreateCidrMask(prefixLength);
            var networkAddress = cidrAddress & mask;
            normalizedValue = $"{FormatIpv4Address(networkAddress)}/{prefixLength}";
            return true;
        }

        if (TryParseAddressRange(trimmed, out var start, out var finish))
        {
            if (start > finish)
            {
                throw new FormatException($"Address range start must be less than or equal to finish: {value}");
            }

            normalizedValue = trimmed;
            return true;
        }

        if (TryParseIpv4Address(trimmed, out var hostValue))
        {
            normalizedValue = $"{FormatIpv4Address(hostValue)}/32";
            return true;
        }

        return false;
    }

    private static bool TryParseCidr(string value, out uint address, out int prefixLength)
    {
        address = 0;
        prefixLength = 0;

        if (!value.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }

        var parts = value.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2
            || !TryParseIpv4Address(parts[0], out address)
            || !int.TryParse(parts[1], out prefixLength)
            || prefixLength is < 0 or > 32)
        {
            return false;
        }

        return true;
    }

    private static bool TryParseAddressRange(string value, out uint start, out uint finish)
    {
        start = 0;
        finish = 0;

        if (!value.Contains('-', StringComparison.Ordinal))
        {
            return false;
        }

        var parts = value.Split('-', 2, StringSplitOptions.TrimEntries);
        return parts.Length == 2
            && TryParseIpv4Address(parts[0], out start)
            && TryParseIpv4Address(parts[1], out finish);
    }

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

    private static uint CreateCidrMask(int prefixLength)
    {
        return prefixLength switch
        {
            0 => 0u,
            32 => uint.MaxValue,
            _ => uint.MaxValue << (32 - prefixLength)
        };
    }

    private static string FormatIpv4Address(uint value)
    {
        return string.Join('.',
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff);
    }
}
