namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// サービス文字列表現とサービス オブジェクトを <see cref="ServiceValue"/> へ変換できる形へ解釈します。
/// </summary>
public static class ServiceValueParser
{
    /// <summary>
    /// 全 IP プロトコルを表す範囲表現です。
    /// </summary>
    private const string AnyProtocolRange = "0-254";

    /// <summary>
    /// 全ポートを表す範囲表現です。
    /// </summary>
    private const string AnyPortRange = "1-65535";

    /// <summary>
    /// サービス参照そのものの any が持つ、Kind 指定も将来包含できるプロトコル範囲表現です。
    /// </summary>
    private const string AnyServiceProtocolRange = "0-255";

    /// <summary>
    /// サービス参照そのものの any が持つ、Kind 指定も将来包含できるポート範囲表現です。
    /// </summary>
    private const string AnyServicePortRange = "0-65535";

    /// <summary>
    /// リポジトリで解決できなかったサービス参照を組み込み指定、直指定、または Kind 指定へ変換します。
    /// </summary>
    /// <param name="value">変換対象のサービス参照。</param>
    /// <returns>変換したサービス オブジェクト。</returns>
    public static ServiceObject ParseObject(string value)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            throw new FormatException("Service reference is required.");
        }

        if (TryNormalizeBuiltInValue(trimmed, out var builtInValue))
        {
            return builtInValue;
        }

        if (TryCreateDirectServiceObject(trimmed, out var directServiceObject))
        {
            return directServiceObject;
        }

        return CreateKindServiceObject(trimmed);
    }

    /// <summary>
    /// サービス オブジェクト内の any 表現を後続処理が解釈できる数値範囲へ正規化します。
    /// </summary>
    /// <param name="serviceObject">正規化対象のサービス オブジェクト。</param>
    /// <returns>正規化したサービス オブジェクト。</returns>
    public static ServiceObject NormalizeObject(ServiceObject serviceObject)
    {
        ArgumentNullException.ThrowIfNull(serviceObject);

        if (IsKindSentinelObject(serviceObject))
        {
            return new ServiceObject
            {
                Name = serviceObject.Name,
                Protocol = serviceObject.Protocol,
                SourcePort = serviceObject.SourcePort,
                DestinationPort = serviceObject.DestinationPort,
                Kind = serviceObject.Kind
            };
        }

        return new ServiceObject
        {
            Name = serviceObject.Name,
            Protocol = NormalizeProtocolValue(serviceObject.Protocol),
            SourcePort = NormalizePortValue(serviceObject.SourcePort),
            DestinationPort = NormalizePortValue(serviceObject.DestinationPort),
            Kind = serviceObject.Kind
        };
    }

    /// <summary>
    /// 組み込みサービス参照をサービス オブジェクトへ正規化します。
    /// </summary>
    /// <param name="value">変換対象のサービス参照。</param>
    /// <param name="normalizedValue">正規化したサービス オブジェクト。</param>
    /// <returns>組み込みサービス参照として解釈できた場合は <see langword="true"/>。</returns>
    public static bool TryNormalizeBuiltInValue(string value, out ServiceObject normalizedValue)
    {
        normalizedValue = null!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.Trim().Equals("any", StringComparison.Ordinal))
        {
            normalizedValue = CreateAnyServiceObject();
            return true;
        }

        return false;
    }

    /// <summary>
    /// サービス オブジェクト 1 件をサービス範囲列へ変換します。
    /// </summary>
    /// <param name="service">変換対象のサービス オブジェクト。</param>
    /// <returns>変換したサービス範囲列。</returns>
    public static IEnumerable<ServiceValue> Parse(ServiceObject service)
    {
        ArgumentNullException.ThrowIfNull(service);

        var protocolRanges = ParseDelimitedRanges(service.Protocol, 0, 255).ToArray();
        var sourcePortRanges = ParseDelimitedRanges(service.SourcePort, 0, 65535).ToArray();
        var destinationPortRanges = ParseDelimitedRanges(service.DestinationPort, 0, 65535).ToArray();

        foreach (var protocolRange in protocolRanges)
        {
            foreach (var sourcePortRange in sourcePortRanges)
            {
                foreach (var destinationPortRange in destinationPortRanges)
                {
                    yield return CreateServiceValue(protocolRange, sourcePortRange, destinationPortRange, service.Kind);
                }
            }
        }
    }

    /// <summary>
    /// 3 要素の直指定サービス表現をサービス オブジェクトへ変換します。
    /// </summary>
    /// <param name="value">直指定候補のサービス表現。</param>
    /// <param name="serviceObject">変換できたサービス オブジェクト。</param>
    /// <returns>直指定として解釈できた場合は <see langword="true"/>。</returns>
    private static bool TryCreateDirectServiceObject(string value, out ServiceObject serviceObject)
    {
        serviceObject = null!;

        var parts = value.Split(new[] { ' ', '\t' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3)
        {
            return false;
        }

        try
        {
            serviceObject = new ServiceObject
            {
                Name = string.Empty,
                Protocol = NormalizeProtocolValue(parts[0]),
                SourcePort = NormalizePortValue(parts[1]),
                DestinationPort = NormalizePortValue(parts[2]),
                Kind = null
            };

            _ = Parse(serviceObject).ToArray();
            return true;
        }
        catch (FormatException)
        {
            serviceObject = null!;
            return false;
        }
    }

    /// <summary>
    /// 全サービスを表すサービス オブジェクトを作成します。
    /// </summary>
    /// <returns>全サービスを表すサービス オブジェクト。</returns>
    private static ServiceObject CreateAnyServiceObject()
    {
        return new ServiceObject
        {
            Name = string.Empty,
            Protocol = AnyServiceProtocolRange,
            SourcePort = AnyServicePortRange,
            DestinationPort = AnyServicePortRange,
            Kind = null
        };
    }

    /// <summary>
    /// Kind 指定を表すサービス オブジェクトを作成します。
    /// </summary>
    /// <param name="kind">Kind 指定。</param>
    /// <returns>Kind 指定を表すサービス オブジェクト。</returns>
    private static ServiceObject CreateKindServiceObject(string kind)
    {
        return new ServiceObject
        {
            Name = string.Empty,
            Protocol = "255",
            SourcePort = "0",
            DestinationPort = "0",
            Kind = kind
        };
    }

    /// <summary>
    /// 3 軸の数値範囲から 1 件のサービス範囲を組み立てます。
    /// </summary>
    /// <param name="protocolRange">プロトコル範囲。</param>
    /// <param name="sourcePortRange">送信元ポート範囲。</param>
    /// <param name="destinationPortRange">宛先ポート範囲。</param>
    /// <param name="kind">サービス種別。</param>
    /// <returns>組み立てたサービス範囲。</returns>
    private static ServiceValue CreateServiceValue(
        SignedRange protocolRange,
        SignedRange sourcePortRange,
        SignedRange destinationPortRange,
        string? kind)
    {
        return new ServiceValue
        {
            ProtocolStart = checked((uint)protocolRange.Start),
            ProtocolFinish = checked((uint)protocolRange.Finish),
            SourcePortStart = checked((uint)sourcePortRange.Start),
            SourcePortFinish = checked((uint)sourcePortRange.Finish),
            DestinationPortStart = checked((uint)destinationPortRange.Start),
            DestinationPortFinish = checked((uint)destinationPortRange.Finish),
            Kind = kind
        };
    }

    /// <summary>
    /// カンマ区切り文字列を数値範囲列へ変換します。
    /// </summary>
    /// <param name="value">変換対象の文字列。</param>
    /// <param name="minimum">許容最小値。</param>
    /// <param name="maximum">許容最大値。</param>
    /// <returns>変換した範囲列。</returns>
    private static IEnumerable<SignedRange> ParseDelimitedRanges(string value, int minimum, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("Range value is required.");
        }

        foreach (var item in value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            yield return ParseSignedRange(item, minimum, maximum);
        }
    }

    /// <summary>
    /// 単一値またはハイフン範囲を数値範囲へ変換します。
    /// </summary>
    /// <param name="value">変換対象の文字列。</param>
    /// <param name="minimum">許容最小値。</param>
    /// <param name="maximum">許容最大値。</param>
    /// <returns>変換した範囲。</returns>
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

    /// <summary>
    /// 数値範囲が許容範囲内かを検証します。
    /// </summary>
    /// <param name="rawValue">元の入力値。</param>
    /// <param name="start">開始値。</param>
    /// <param name="finish">終了値。</param>
    /// <param name="minimum">許容最小値。</param>
    /// <param name="maximum">許容最大値。</param>
    private static void ValidateRange(string rawValue, int start, int finish, int minimum, int maximum)
    {
        if (start < minimum || finish > maximum || start > finish)
        {
            throw new FormatException($"Value is out of range: {rawValue}");
        }
    }

    /// <summary>
    /// プロトコル表現を後続処理が解釈できる数値表現へ正規化します。
    /// </summary>
    /// <param name="protocol">正規化対象のプロトコル表現。</param>
    /// <returns>正規化したプロトコル表現。</returns>
    private static string NormalizeProtocolValue(string protocol)
    {
        var trimmed = protocol.Trim();
        if (trimmed.Equals("any", StringComparison.Ordinal))
        {
            return AnyProtocolRange;
        }

        return NormalizeDelimitedRangeValue(trimmed, NormalizeProtocolRangeItem);
    }

    /// <summary>
    /// ポート表現の any を後続処理が解釈できる数値範囲へ正規化します。
    /// </summary>
    /// <param name="port">正規化対象のポート表現。</param>
    /// <returns>正規化したポート表現。</returns>
    private static string NormalizePortValue(string port)
    {
        var trimmed = port.Trim();

        if (trimmed.Equals("any", StringComparison.Ordinal))
        {
            return AnyPortRange;
        }

        return NormalizeDelimitedRangeValue(trimmed, NormalizePortRangeItem);
    }

    /// <summary>
    /// カンマ区切りの数値範囲表現を、各要素ごとに正規化します。
    /// </summary>
    /// <param name="value">正規化対象の範囲表現。</param>
    /// <param name="normalizeItem">要素単位の正規化処理。</param>
    /// <returns>正規化した範囲表現。</returns>
    private static string NormalizeDelimitedRangeValue(string value, Func<string, string> normalizeItem)
    {
        ArgumentNullException.ThrowIfNull(normalizeItem);

        var items = value
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(normalizeItem)
            .ToArray();

        if (items.Length == 0)
        {
            throw new FormatException("Range value is required.");
        }

        return string.Join(",", items);
    }

    /// <summary>
    /// IP プロトコル番号範囲の終端 255 を 254 へ丸めます。
    /// </summary>
    /// <param name="value">正規化対象のプロトコル範囲要素。</param>
    /// <returns>正規化したプロトコル範囲要素。</returns>
    private static string NormalizeProtocolRangeItem(string value)
    {
        if (!value.Contains('-', StringComparison.Ordinal))
        {
            return ResolveProtocolNumber(value).ToString();
        }

        var range = ParseSignedRange(value, 0, 255);
        var finish = range.Finish == 255 ? 254 : range.Finish;
        if (range.Start > finish)
        {
            throw new FormatException($"Value is out of range: {value}");
        }

        return range.Start == finish
            ? range.Start.ToString()
            : $"{range.Start}-{finish}";
    }

    /// <summary>
    /// ポート番号範囲の開始 0 を 1 へ丸めます。
    /// </summary>
    /// <param name="value">正規化対象のポート範囲要素。</param>
    /// <returns>正規化したポート範囲要素。</returns>
    private static string NormalizePortRangeItem(string value)
    {
        if (value.Equals("any", StringComparison.Ordinal))
        {
            return AnyPortRange;
        }

        var range = ParseSignedRange(value, 0, 65535);
        var start = range.Start == 0 ? 1 : range.Start;
        var finish = range.Finish == 0 ? 1 : range.Finish;
        if (start > finish)
        {
            throw new FormatException($"Value is out of range: {value}");
        }

        return start == finish
            ? start.ToString()
            : $"{start}-{finish}";
    }

    /// <summary>
    /// Kind 指定を表すための番兵サービス オブジェクトかを判定します。
    /// </summary>
    /// <param name="serviceObject">判定対象のサービス オブジェクト。</param>
    /// <returns>Kind 指定用の番兵表現であれば <see langword="true"/>。</returns>
    private static bool IsKindSentinelObject(ServiceObject serviceObject)
    {
        return !string.IsNullOrWhiteSpace(serviceObject.Kind)
            && serviceObject.Protocol.Trim().Equals("255", StringComparison.Ordinal)
            && serviceObject.SourcePort.Trim().Equals("0", StringComparison.Ordinal)
            && serviceObject.DestinationPort.Trim().Equals("0", StringComparison.Ordinal);
    }

    /// <summary>
    /// プロトコル名または番号を IP プロトコル番号へ解決します。
    /// </summary>
    /// <param name="protocol">プロトコル名または番号。</param>
    /// <returns>IP プロトコル番号。</returns>
    private static int ResolveProtocolNumber(string protocol)
    {
        return protocol.Trim().ToUpperInvariant() switch
        {
            "TCP" => 6,
            "UDP" => 17,
            "ICMP" => 1,
            "SCTP" => 132,
            _ => int.TryParse(protocol, out var numericProtocol)
                ? numericProtocol
                : throw new FormatException($"Unsupported protocol: {protocol}")
        };
    }

    /// <summary>
    /// サービス範囲解析の内部表現です。
    /// </summary>
    /// <param name="Start">開始値。</param>
    /// <param name="Finish">終了値。</param>
    private readonly record struct SignedRange(int Start, int Finish);
}
