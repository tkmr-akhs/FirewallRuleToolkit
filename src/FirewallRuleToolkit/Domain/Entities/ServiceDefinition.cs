namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// import 済みの名前付きサービス定義を保持します。
/// </summary>
public sealed class ServiceDefinition
{
    /// <summary>
    /// サービス定義名を取得します。
    /// </summary>
    public required string Name { get; init; } = string.Empty;

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
