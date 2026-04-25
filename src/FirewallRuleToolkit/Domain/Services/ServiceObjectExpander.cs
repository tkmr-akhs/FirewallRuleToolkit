namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// サービス オブジェクトを数値範囲へ正規化し、必要に応じて単一値へ展開します。
/// </summary>
internal static class ServiceObjectExpander
{
    /// <summary>
    /// サービス オブジェクト群を、必要に応じて単一値まで展開したサービス範囲列へ変換します。
    /// </summary>
    /// <param name="services">変換対象のサービス オブジェクト列。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後のサービス範囲列。</returns>
    public static IEnumerable<ServiceValue> Expand(IEnumerable<ServiceObject> services, int threshold)
    {
        ArgumentNullException.ThrowIfNull(services);
        ValidateThreshold(threshold);

        foreach (var service in services)
        {
            foreach (var expanded in Expand(service, threshold))
            {
                yield return expanded;
            }
        }
    }

    /// <summary>
    /// サービス オブジェクト 1 件をサービス範囲列へ変換します。
    /// </summary>
    /// <param name="service">変換対象のサービス オブジェクト。</param>
    /// <returns>変換したサービス範囲列。</returns>
    public static IEnumerable<ServiceValue> Parse(ServiceObject service)
    {
        return ServiceValueParser.Parse(service);
    }

    /// <summary>
    /// サービス オブジェクト 1 件を、必要に応じて単一値まで展開したサービス範囲列へ変換します。
    /// </summary>
    /// <param name="service">変換対象のサービス オブジェクト。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後のサービス範囲列。</returns>
    public static IEnumerable<ServiceValue> Expand(ServiceObject service, int threshold)
    {
        ArgumentNullException.ThrowIfNull(service);
        ValidateThreshold(threshold);

        foreach (var parsed in ServiceValueParser.Parse(service))
        {
            var protocolRanges = ExpandRange(parsed.ProtocolStart, parsed.ProtocolFinish, threshold).ToArray();
            var sourcePortRanges = ExpandRange(parsed.SourcePortStart, parsed.SourcePortFinish, threshold).ToArray();
            var destinationPortRanges = ExpandRange(parsed.DestinationPortStart, parsed.DestinationPortFinish, threshold).ToArray();

            foreach (var protocolRange in protocolRanges)
            {
                foreach (var sourcePortRange in sourcePortRanges)
                {
                    foreach (var destinationPortRange in destinationPortRanges)
                    {
                        yield return CreateServiceValue(protocolRange, sourcePortRange, destinationPortRange, parsed.Kind);
                    }
                }
            }
        }
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
        UnsignedRange protocolRange,
        UnsignedRange sourcePortRange,
        UnsignedRange destinationPortRange,
        string? kind)
    {
        return new ServiceValue
        {
            ProtocolStart = protocolRange.Start,
            ProtocolFinish = protocolRange.Finish,
            SourcePortStart = sourcePortRange.Start,
            SourcePortFinish = sourcePortRange.Finish,
            DestinationPortStart = destinationPortRange.Start,
            DestinationPortFinish = destinationPortRange.Finish,
            Kind = kind
        };
    }

    /// <summary>
    /// 数値範囲を必要に応じて単一値へ展開します。
    /// </summary>
    /// <param name="start">開始値。</param>
    /// <param name="finish">終了値。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後の範囲列。</returns>
    private static IEnumerable<UnsignedRange> ExpandRange(uint start, uint finish, int threshold)
    {
        var count = (ulong)finish - start + 1UL;
        if (count >= (ulong)threshold)
        {
            yield return new UnsignedRange(start, finish);
            yield break;
        }

        for (var value = start; ; value++)
        {
            yield return new UnsignedRange(value, value);

            if (value == finish)
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// しきい値が有効かを検証します。
    /// </summary>
    /// <param name="threshold">検証対象のしきい値。</param>
    private static void ValidateThreshold(int threshold)
    {
        if (threshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "Threshold must be greater than zero.");
        }
    }

    /// <summary>
    /// サービス範囲展開の内部表現です。
    /// </summary>
    /// <param name="Start">開始値。</param>
    /// <param name="Finish">終了値。</param>
    private readonly record struct UnsignedRange(uint Start, uint Finish);
}
