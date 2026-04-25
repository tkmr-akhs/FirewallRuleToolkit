namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// 単一のアドレス オブジェクトを保持します。
/// </summary>
public sealed class AddressObject
{
    /// <summary>
    /// オブジェクト名を取得します。
    /// </summary>
    public required string Name { get; init; } = String.Empty;

    /// <summary>
    /// アドレス値を取得します。
    /// </summary>
    public required string Value { get; init; }
}
