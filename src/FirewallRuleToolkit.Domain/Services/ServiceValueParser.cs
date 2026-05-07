namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// サービス文字列表現と名前付きサービス定義を <see cref="ServiceValue"/> へ変換できる形へ検証・解釈します。
/// </summary>
public static class ServiceValueParser
{
    /// <summary>
    /// サービス参照そのものの any が持つ、Kind 指定も将来包含できるプロトコル範囲表現です。
    /// </summary>
    private const string AnyServiceProtocolRange = "0-255";

    /// <summary>
    /// サービス参照そのものの any が持つ、Kind 指定も将来包含できるポート範囲表現です。
    /// </summary>
    private const string AnyServicePortRange = "0-65535";

    /// <summary>
    /// リポジトリで解決できなかったサービス参照を組み込み指定、canonical 直指定、または Kind 指定へ分類します。
    /// </summary>
    /// <param name="value">変換対象のサービス参照。</param>
    /// <returns>変換した解決済みサービス定義。</returns>
    public static ResolvedService ParseReference(string value)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            throw new FormatException("Service reference is required.");
        }

        if (TryCreateBuiltInValue(trimmed, out var builtInValue))
        {
            return builtInValue;
        }

        if (TryParseCanonicalDirectReference(trimmed, out var directService))
        {
            return directService;
        }

        return CreateKindResolvedService(trimmed);
    }

    /// <summary>
    /// 名前付きサービス定義を canonical な解決済みサービス定義として検証・変換します。
    /// </summary>
    /// <param name="serviceDefinition">検証対象の名前付きサービス定義。</param>
    /// <returns>検証済みの解決済みサービス定義。</returns>
    public static ResolvedService ParseDefinition(ServiceDefinition serviceDefinition)
    {
        ArgumentNullException.ThrowIfNull(serviceDefinition);

        if (IsKindSentinelDefinition(serviceDefinition))
        {
            return new ResolvedService
            {
                Protocol = serviceDefinition.Protocol,
                SourcePort = serviceDefinition.SourcePort,
                DestinationPort = serviceDefinition.DestinationPort,
                Kind = serviceDefinition.Kind
            };
        }

        if (!string.IsNullOrWhiteSpace(serviceDefinition.Kind))
        {
            throw new FormatException("Kind service definition must use the Kind sentinel range.");
        }

        var resolvedService = new ResolvedService
        {
            Protocol = TrimRequired(serviceDefinition.Protocol, "Protocol"),
            SourcePort = TrimRequired(serviceDefinition.SourcePort, "Source port"),
            DestinationPort = TrimRequired(serviceDefinition.DestinationPort, "Destination port"),
            Kind = null
        };

        ValidateDirectService(resolvedService);
        return resolvedService;
    }

    /// <summary>
    /// 組み込みサービス参照を解決済みサービス定義として解釈します。
    /// </summary>
    /// <param name="value">変換対象のサービス参照。</param>
    /// <param name="resolvedValue">解釈した解決済みサービス定義。</param>
    /// <returns>組み込みサービス参照として解釈できた場合は <see langword="true"/>。</returns>
    public static bool TryCreateBuiltInValue(string value, out ResolvedService resolvedValue)
    {
        resolvedValue = default;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (value.Trim().Equals("any", StringComparison.Ordinal))
        {
            resolvedValue = CreateAnyResolvedService();
            return true;
        }

        return false;
    }

    /// <summary>
    /// 3 要素の canonical 直指定サービス表現を解決済みサービス定義へ変換します。
    /// </summary>
    /// <param name="value">直指定候補のサービス表現。</param>
    /// <param name="service">変換できた解決済みサービス定義。</param>
    /// <returns>canonical 直指定として解釈できた場合は <see langword="true"/>。</returns>
    public static bool TryParseCanonicalDirectReference(string value, out ResolvedService service)
    {
        service = default;

        var parts = SplitServiceReferenceParts(value);
        if (parts.Length != 3)
        {
            return false;
        }

        var candidate = new ResolvedService
        {
            Protocol = parts[0],
            SourcePort = parts[1],
            DestinationPort = parts[2],
            Kind = null
        };

        try
        {
            ValidateDirectService(candidate);
        }
        catch (FormatException)
        {
            return false;
        }

        service = candidate;
        return true;
    }

    /// <summary>
    /// 未解決サービス参照を Kind 指定として表す解決済みサービス定義を作成します。
    /// </summary>
    /// <param name="kind">Kind 指定。</param>
    /// <returns>Kind 指定を表す解決済みサービス定義。</returns>
    public static ResolvedService CreateKindResolvedService(string kind)
    {
        return new ResolvedService
        {
            Protocol = "255",
            SourcePort = "0",
            DestinationPort = "0",
            Kind = TrimRequired(kind, "Service kind")
        };
    }

    /// <summary>
    /// 解決済みサービス定義 1 件をサービス範囲列へ変換します。
    /// </summary>
    /// <param name="service">変換対象の解決済みサービス定義。</param>
    /// <returns>変換したサービス範囲列。</returns>
    public static IEnumerable<ServiceValue> Parse(ResolvedService service)
    {
        SignedRange[] protocolRanges;
        SignedRange[] sourcePortRanges;
        SignedRange[] destinationPortRanges;

        if (IsKindSentinelService(service))
        {
            protocolRanges = ParseDelimitedRanges(service.Protocol, 255, 255).ToArray();
            sourcePortRanges = ParseDelimitedRanges(service.SourcePort, 0, 0).ToArray();
            destinationPortRanges = ParseDelimitedRanges(service.DestinationPort, 0, 0).ToArray();
        }
        else if (IsBuiltInAnyService(service))
        {
            protocolRanges = ParseDelimitedRanges(service.Protocol, 0, 255).ToArray();
            sourcePortRanges = ParseDelimitedRanges(service.SourcePort, 0, 65535).ToArray();
            destinationPortRanges = ParseDelimitedRanges(service.DestinationPort, 0, 65535).ToArray();
        }
        else
        {
            if (service.Kind is not null)
            {
                throw new FormatException("Kind service must use the Kind sentinel range.");
            }

            protocolRanges = ParseDelimitedRanges(service.Protocol, 0, 254).ToArray();
            sourcePortRanges = ParseDelimitedRanges(service.SourcePort, 1, 65535).ToArray();
            destinationPortRanges = ParseDelimitedRanges(service.DestinationPort, 1, 65535).ToArray();
        }

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
    /// 全サービスを表す解決済みサービス定義を作成します。
    /// </summary>
    /// <returns>全サービスを表す解決済みサービス定義。</returns>
    private static ResolvedService CreateAnyResolvedService()
    {
        return new ResolvedService
        {
            Protocol = AnyServiceProtocolRange,
            SourcePort = AnyServicePortRange,
            DestinationPort = AnyServicePortRange,
            Kind = null
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
    /// 直指定サービスとして妥当な数値範囲だけで構成されているか検証します。
    /// </summary>
    /// <param name="service">検証対象の解決済みサービス定義。</param>
    private static void ValidateDirectService(ResolvedService service)
    {
        _ = ParseDelimitedRanges(service.Protocol, 0, 254).ToArray();
        _ = ParseDelimitedRanges(service.SourcePort, 1, 65535).ToArray();
        _ = ParseDelimitedRanges(service.DestinationPort, 1, 65535).ToArray();
    }

    /// <summary>
    /// サービス参照文字列を空白区切りの要素へ分割します。
    /// </summary>
    /// <param name="value">分割対象のサービス参照。</param>
    /// <returns>空白区切りの要素列。</returns>
    internal static string[] SplitServiceReferenceParts(string value)
    {
        return value.Split(new[] { ' ', '\t' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// 必須文字列値を trim します。
    /// </summary>
    /// <param name="value">対象文字列。</param>
    /// <param name="fieldName">診断用の項目名。</param>
    /// <returns>trim 後の文字列。</returns>
    private static string TrimRequired(string value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException($"{fieldName} is required.");
        }

        return value.Trim();
    }

    /// <summary>
    /// サービス参照そのものの組み込み any かを判定します。
    /// </summary>
    /// <param name="service">判定対象の解決済みサービス定義。</param>
    /// <returns>組み込み any であれば <see langword="true"/>。</returns>
    private static bool IsBuiltInAnyService(ResolvedService service)
    {
        return service.Kind is null
            && service.Protocol.Trim().Equals(AnyServiceProtocolRange, StringComparison.Ordinal)
            && service.SourcePort.Trim().Equals(AnyServicePortRange, StringComparison.Ordinal)
            && service.DestinationPort.Trim().Equals(AnyServicePortRange, StringComparison.Ordinal);
    }

    /// <summary>
    /// Kind 指定を表すための番兵サービスかを判定します。
    /// </summary>
    /// <param name="service">判定対象の解決済みサービス定義。</param>
    /// <returns>Kind 指定用の番兵表現であれば <see langword="true"/>。</returns>
    private static bool IsKindSentinelService(ResolvedService service)
    {
        return !string.IsNullOrWhiteSpace(service.Kind)
            && service.Protocol.Trim().Equals("255", StringComparison.Ordinal)
            && service.SourcePort.Trim().Equals("0", StringComparison.Ordinal)
            && service.DestinationPort.Trim().Equals("0", StringComparison.Ordinal);
    }

    /// <summary>
    /// Kind 指定を表すための番兵サービス定義かを判定します。
    /// </summary>
    /// <param name="serviceDefinition">判定対象のサービス定義。</param>
    /// <returns>Kind 指定用の番兵表現であれば <see langword="true"/>。</returns>
    private static bool IsKindSentinelDefinition(ServiceDefinition serviceDefinition)
    {
        return !string.IsNullOrWhiteSpace(serviceDefinition.Kind)
            && serviceDefinition.Protocol.Trim().Equals("255", StringComparison.Ordinal)
            && serviceDefinition.SourcePort.Trim().Equals("0", StringComparison.Ordinal)
            && serviceDefinition.DestinationPort.Trim().Equals("0", StringComparison.Ordinal);
    }

    /// <summary>
    /// サービス範囲解析の内部表現です。
    /// </summary>
    /// <param name="Start">開始値。</param>
    /// <param name="Finish">終了値。</param>
    private readonly record struct SignedRange(int Start, int Finish);
}
