namespace FirewallRuleToolkit.Infra.Csv.PaloAlto;

/// <summary>
/// Palo Alto CSV のサービス表記を Domain が解釈できる canonical 表記へ変換します。
/// </summary>
internal static class PaloAltoServiceValueNormalizer
{
    private const string DirectAnyProtocolRange = "0-254";
    private const string DirectAnyPortRange = "1-65535";

    /// <summary>
    /// 名前付きサービス定義の protocol 値を canonical 表記へ正規化します。
    /// </summary>
    /// <param name="protocol">Palo Alto CSV の protocol 値。</param>
    /// <returns>canonical protocol 値。</returns>
    public static string NormalizeDefinitionProtocol(string protocol)
    {
        return NormalizeDelimitedRangeValue(
            protocol,
            static item => NormalizeProtocolItem(item, allowCaseInsensitiveAlias: true, allowCaseInsensitiveAny: true, allowProtocol255Endpoint: true));
    }

    /// <summary>
    /// 名前付きサービス定義の port 値を canonical 表記へ正規化します。
    /// </summary>
    /// <param name="port">Palo Alto CSV の port 値。</param>
    /// <returns>canonical port 値。</returns>
    public static string NormalizeDefinitionPortValue(string port)
    {
        var items = new List<string>();
        foreach (var item in SplitDelimitedItems(port))
        {
            var normalizedItem = NormalizeDefinitionPortItem(item);
            if (normalizedItem is not null)
            {
                items.Add(normalizedItem);
            }
        }

        if (items.Count == 0)
        {
            throw new FormatException("Port value is required.");
        }

        return string.Join(",", items);
    }

    /// <summary>
    /// ポリシーまたはグループのサービス参照欄にある直接サービス値だけを canonical 表記へ正規化します。
    /// </summary>
    /// <param name="value">Palo Alto CSV のサービス参照。</param>
    /// <returns>正規化できた直接サービス値、または元の参照名。</returns>
    public static string NormalizePolicyServiceReference(string value)
    {
        return TryNormalizePolicyDirectService(value, out var normalizedValue)
            ? normalizedValue
            : value.Trim();
    }

    private static bool TryNormalizePolicyDirectService(string value, out string normalizedValue)
    {
        normalizedValue = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var parts = value.Split(new[] { ' ', '\t' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
        {
            return false;
        }

        try
        {
            var protocol = NormalizeDelimitedRangeValue(
                parts[0],
                static item => NormalizeProtocolItem(item, allowCaseInsensitiveAlias: false, allowCaseInsensitiveAny: false, allowProtocol255Endpoint: false));
            var sourcePort = NormalizeDelimitedRangeValue(parts[1], NormalizePolicyPortItem);
            var destinationPort = NormalizeDelimitedRangeValue(parts[2], NormalizePolicyPortItem);
            normalizedValue = $"{protocol} {sourcePort} {destinationPort}";
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string? NormalizeDefinitionPortItem(string port)
    {
        if (port.Equals("any", StringComparison.OrdinalIgnoreCase))
        {
            return DirectAnyPortRange;
        }

        if (port.Equals("0", StringComparison.Ordinal))
        {
            return null;
        }

        string normalizedValue;
        if (port.StartsWith("0-", StringComparison.Ordinal))
        {
            var finish = port[2..];
            if (finish.Equals("0", StringComparison.Ordinal))
            {
                return null;
            }

            normalizedValue = finish.Equals("1", StringComparison.Ordinal)
                ? "1"
                : $"1-{finish}";
        }
        else
        {
            normalizedValue = port;
        }

        _ = ParseSignedRange(normalizedValue, 1, 65535);
        return normalizedValue;
    }

    private static string NormalizePolicyPortItem(string port)
    {
        if (port.Equals("any", StringComparison.Ordinal))
        {
            return DirectAnyPortRange;
        }

        _ = ParseSignedRange(port, 1, 65535);
        return port;
    }

    private static string NormalizeProtocolItem(
        string protocol,
        bool allowCaseInsensitiveAlias,
        bool allowCaseInsensitiveAny,
        bool allowProtocol255Endpoint)
    {
        if (IsProtocolAny(protocol, allowCaseInsensitiveAny))
        {
            return DirectAnyProtocolRange;
        }

        if (TryResolveProtocolAlias(protocol, allowCaseInsensitiveAlias, out var protocolNumber))
        {
            return protocolNumber.ToString();
        }

        var maximum = allowProtocol255Endpoint ? 255 : 254;
        var range = ParseSignedRange(protocol, 0, maximum);
        var finish = allowProtocol255Endpoint && range.Finish == 255
            ? 254
            : range.Finish;
        if (range.Start > finish)
        {
            throw new FormatException($"Value is out of range: {protocol}");
        }

        return range.Start == finish
            ? range.Start.ToString()
            : $"{range.Start}-{finish}";
    }

    private static string NormalizeDelimitedRangeValue(string value, Func<string, string> normalizeItem)
    {
        var items = SplitDelimitedItems(value)
            .Select(normalizeItem)
            .ToArray();

        if (items.Length == 0)
        {
            throw new FormatException("Range value is required.");
        }

        return string.Join(",", items);
    }

    private static IEnumerable<string> SplitDelimitedItems(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            yield break;
        }

        foreach (var item in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            yield return item;
        }
    }

    private static bool IsProtocolAny(string protocol, bool allowCaseInsensitiveAny)
    {
        return allowCaseInsensitiveAny
            ? protocol.Equals("any", StringComparison.OrdinalIgnoreCase)
            : protocol.Equals("any", StringComparison.Ordinal);
    }

    private static bool TryResolveProtocolAlias(string protocol, bool allowCaseInsensitiveAlias, out int protocolNumber)
    {
        var comparison = allowCaseInsensitiveAlias
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (protocol.Equals("tcp", comparison))
        {
            protocolNumber = 6;
            return true;
        }

        if (protocol.Equals("udp", comparison))
        {
            protocolNumber = 17;
            return true;
        }

        if (protocol.Equals("icmp", comparison))
        {
            protocolNumber = 1;
            return true;
        }

        if (protocol.Equals("sctp", comparison))
        {
            protocolNumber = 132;
            return true;
        }

        protocolNumber = 0;
        return false;
    }

    private static SignedRange ParseSignedRange(string value, int minimum, int maximum)
    {
        if (value.Contains('-', StringComparison.Ordinal))
        {
            var parts = value.Split('-', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2
                || !int.TryParse(parts[0], out var start)
                || !int.TryParse(parts[1], out var finish))
            {
                throw new FormatException($"Unsupported numeric range: {value}");
            }

            ValidateRange(value, start, finish, minimum, maximum);
            return new SignedRange(start, finish);
        }

        if (!int.TryParse(value, out var numericValue))
        {
            throw new FormatException($"Unsupported numeric value: {value}");
        }

        ValidateRange(value, numericValue, numericValue, minimum, maximum);
        return new SignedRange(numericValue, numericValue);
    }

    private static void ValidateRange(string rawValue, int start, int finish, int minimum, int maximum)
    {
        if (start < minimum || finish > maximum || start > finish)
        {
            throw new FormatException($"Value is out of range: {rawValue}");
        }
    }

    private readonly record struct SignedRange(int Start, int Finish);
}
