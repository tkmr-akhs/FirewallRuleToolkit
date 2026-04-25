namespace FirewallRuleToolkit.Domain.ValueObjects;

/// <summary>
/// アドレス値の範囲を表します。
/// </summary>
public readonly struct AddressValue
{
    /// <summary>
    /// 範囲の開始値を取得します。
    /// </summary>
    public uint Start { get; init; }

    /// <summary>
    /// 範囲の終了値を取得します。
    /// </summary>
    public uint Finish { get; init; }
}
