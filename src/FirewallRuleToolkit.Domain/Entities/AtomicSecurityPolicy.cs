namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// 1 組み合わせ単位に分解されたセキュリティ ポリシーを保持します。
/// </summary>
public sealed class AtomicSecurityPolicy
{
    /// <summary>
    /// 送信元ゾーンを取得します。
    /// </summary>
    public required string FromZone { get; init; }

    /// <summary>
    /// 送信元アドレス値を取得します。
    /// </summary>
    public required AddressValue SourceAddress { get; init; }

    /// <summary>
    /// 宛先ゾーンを取得します。
    /// </summary>
    public required string ToZone { get; init; }

    /// <summary>
    /// 宛先アドレス値を取得します。
    /// </summary>
    public required AddressValue DestinationAddress { get; init; }

    /// <summary>
    /// アプリケーションを取得します。
    /// </summary>
    public required string Application { get; init; }

    /// <summary>
    /// サービス値を取得します。
    /// </summary>
    public required ServiceValue Service { get; init; }

    /// <summary>
    /// アクションを取得します。
    /// </summary>
    public required SecurityPolicyAction Action { get; init; }

    /// <summary>
    /// グループ識別子を取得します。
    /// </summary>
    public required string GroupId { get; init; }

    /// <summary>
    /// 元ポリシーのインデックスを取得します。
    /// </summary>
    public required uint OriginalIndex { get; init; }

    /// <summary>
    /// 元ポリシー名を取得します。
    /// </summary>
    public required string OriginalPolicyName { get; init; }
}
