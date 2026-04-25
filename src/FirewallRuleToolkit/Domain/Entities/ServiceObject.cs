namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// 単一のサービス オブジェクトを保持します。
/// </summary>
public sealed class ServiceObject
{
    /// <summary>
    /// オブジェクト名を取得します。
    /// </summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// IP プロトコルを取得します。
    /// </summary>
    public required string Protocol { get; init; }

    /// <summary>
    /// 送信元ポート定義を取得します。
    /// </summary>
    public required string SourcePort { get; init; }

    /// <summary>
    /// 宛先ポート定義を取得します。
    /// </summary>
    public required string DestinationPort { get; init; }

    /// <summary>
    /// サービスの種別を取得します。
    /// </summary>
    public required string? Kind { get; init; }
}
