namespace FirewallRuleToolkit.Domain.ValueObjects;

/// <summary>
/// 参照解決後の匿名サービス定義を表します。
/// </summary>
public readonly struct ResolvedService
{
    /// <summary>
    /// IP プロトコル表現を取得します。
    /// </summary>
    public required string Protocol { get; init; }

    /// <summary>
    /// 送信元ポート表現を取得します。
    /// </summary>
    public required string SourcePort { get; init; }

    /// <summary>
    /// 宛先ポート表現を取得します。
    /// </summary>
    public required string DestinationPort { get; init; }

    /// <summary>
    /// サービスの種別を取得します。
    /// </summary>
    public required string? Kind { get; init; }
}
