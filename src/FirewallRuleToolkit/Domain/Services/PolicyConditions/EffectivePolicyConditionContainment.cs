namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// 実際のルール評価として、片方の条件がもう片方を覆うかを判定します。
/// </summary>
internal static class EffectivePolicyConditionContainment
{
    /// <summary>
    /// アドレス範囲が被包含側をルール評価上覆っているかを判定します。
    /// </summary>
    /// <param name="container">包含側アドレス。</param>
    /// <param name="contained">被包含側アドレス。</param>
    /// <returns>包含するとき <see langword="true"/>。</returns>
    public static bool AddressCovers(AddressValue container, AddressValue contained)
    {
        return container.Start <= contained.Start
            && container.Finish >= contained.Finish;
    }

    /// <summary>
    /// サービス範囲が被包含側をルール評価上覆っているかを判定します。
    /// </summary>
    /// <param name="container">包含側サービス。</param>
    /// <param name="contained">被包含側サービス。</param>
    /// <returns>包含するとき <see langword="true"/>。</returns>
    public static bool ServiceCovers(ServiceValue container, ServiceValue contained)
    {
        return container.ProtocolStart <= contained.ProtocolStart
            && container.ProtocolFinish >= contained.ProtocolFinish
            && container.SourcePortStart <= contained.SourcePortStart
            && container.SourcePortFinish >= contained.SourcePortFinish
            && container.DestinationPortStart <= contained.DestinationPortStart
            && container.DestinationPortFinish >= contained.DestinationPortFinish
            && string.Equals(container.Kind, contained.Kind, StringComparison.Ordinal);
    }

    /// <summary>
    /// アプリケーションが被包含側をルール評価上覆っているかを判定します。
    /// </summary>
    /// <param name="container">包含側アプリケーション。</param>
    /// <param name="contained">被包含側アプリケーション。</param>
    /// <returns>包含するとき <see langword="true"/>。</returns>
    public static bool ApplicationCovers(string container, string contained)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(container);
        ArgumentException.ThrowIfNullOrWhiteSpace(contained);

        return string.Equals(container, contained, StringComparison.Ordinal)
            || string.Equals(container, "any", StringComparison.OrdinalIgnoreCase);
    }
}
