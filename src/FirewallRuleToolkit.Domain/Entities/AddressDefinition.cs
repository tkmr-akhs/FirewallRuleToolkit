namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// import 済みの名前付きアドレス定義を保持します。
/// </summary>
public sealed class AddressDefinition
{
    /// <summary>
    /// アドレス定義名を取得します。
    /// </summary>
    public required string Name { get; init; } = string.Empty;

    /// <summary>
    /// アドレス値表現を取得します。
    /// </summary>
    public required string Value { get; init; }
}
