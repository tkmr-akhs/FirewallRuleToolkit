namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// import 後に Domain が扱うポリシー条件値の標準順を提供します。
/// </summary>
internal static class PolicyConditionCanonicalOrder
{
    /// <summary>
    /// アドレス条件値を数値範囲の標準順へ並べます。
    /// </summary>
    /// <param name="values">対象アドレス条件値。</param>
    /// <returns>標準順に並んだアドレス条件値。</returns>
    public static IOrderedEnumerable<AddressValue> OrderAddresses(IEnumerable<AddressValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values
            .OrderBy(static value => value.Start)
            .ThenBy(static value => value.Finish);
    }

    /// <summary>
    /// サービス条件値を標準順へ並べます。
    /// </summary>
    /// <param name="values">対象サービス条件値。</param>
    /// <returns>標準順に並んだサービス条件値。</returns>
    public static IOrderedEnumerable<ServiceValue> OrderServices(IEnumerable<ServiceValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values
            .OrderBy(GetServiceCategory)
            .ThenBy(static value => value.Kind, StringComparer.Ordinal)
            .ThenBy(static value => value.ProtocolStart)
            .ThenBy(static value => value.ProtocolFinish)
            .ThenBy(static value => value.DestinationPortStart)
            .ThenBy(static value => value.DestinationPortFinish)
            .ThenBy(static value => value.SourcePortStart)
            .ThenBy(static value => value.SourcePortFinish);
    }

    /// <summary>
    /// アプリケーション条件値を標準順へ並べます。
    /// </summary>
    /// <param name="values">対象アプリケーション条件値。</param>
    /// <returns>標準順に並んだアプリケーション条件値。</returns>
    public static IOrderedEnumerable<string> OrderApplications(IEnumerable<string> values)
    {
        return OrderOrdinalStrings(values);
    }

    /// <summary>
    /// 通常の文字列値を Ordinal 比較の標準順へ並べます。
    /// </summary>
    /// <param name="values">対象文字列値。</param>
    /// <returns>標準順に並んだ文字列値。</returns>
    public static IOrderedEnumerable<string> OrderOrdinalStrings(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values.OrderBy(static value => value, StringComparer.Ordinal);
    }

    /// <summary>
    /// サービス参照そのものの組み込み any かどうかを判定します。
    /// </summary>
    /// <param name="value">判定対象のサービス条件値。</param>
    /// <returns>組み込み any であれば <see langword="true"/>。</returns>
    public static bool IsBuiltInAnyService(ServiceValue value)
    {
        return string.IsNullOrWhiteSpace(value.Kind)
            && value.ProtocolStart == 0U
            && value.ProtocolFinish == 255U
            && value.SourcePortStart == 0U
            && value.SourcePortFinish == 65535U
            && value.DestinationPortStart == 0U
            && value.DestinationPortFinish == 65535U;
    }

    /// <summary>
    /// サービス条件値の大分類を返します。
    /// </summary>
    /// <param name="value">対象サービス条件値。</param>
    /// <returns>組み込み any、Kind、3 軸指定の順に対応する分類値。</returns>
    private static int GetServiceCategory(ServiceValue value)
    {
        if (IsBuiltInAnyService(value))
        {
            return 0;
        }

        return string.IsNullOrWhiteSpace(value.Kind) ? 2 : 1;
    }
}
