namespace FirewallRuleToolkit.Domain.ValueObjects;

/// <summary>
/// 参照解決後の匿名アドレス値表現を表します。
/// </summary>
public readonly struct ResolvedAddress
{
    /// <summary>
    /// アドレス値表現を取得します。
    /// </summary>
    public required string Value { get; init; }
}
