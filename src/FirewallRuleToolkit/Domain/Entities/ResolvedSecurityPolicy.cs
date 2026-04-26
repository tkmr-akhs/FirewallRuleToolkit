namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// 解決済みで、まだ atomic 化されていないセキュリティ ポリシー 1 件分の情報を保持します。
/// </summary>
internal sealed class ResolvedSecurityPolicy
{
    /// <summary>
    /// ポリシー インデックスを取得します。
    /// </summary>
    public required uint Index { get; init; }

    /// <summary>
    /// ポリシー名を取得します。
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 送信元ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> FromZones { get; init; }

    /// <summary>
    /// 送信元アドレス一覧を取得します。
    /// </summary>
    public required IReadOnlyList<AddressObject> SourceAddresses { get; init; }

    /// <summary>
    /// 宛先ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> ToZones { get; init; }

    /// <summary>
    /// 宛先アドレス一覧を取得します。
    /// </summary>
    public required IReadOnlyList<AddressObject> DestinationAddresses { get; init; }

    /// <summary>
    /// アプリケーション一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> Applications { get; init; }

    /// <summary>
    /// サービス定義一覧を取得します。
    /// </summary>
    public required IReadOnlyList<ServiceObject> Services { get; init; }

    /// <summary>
    /// アクションを取得します。
    /// </summary>
    public required SecurityPolicyAction Action { get; init; }

    /// <summary>
    /// グループ識別子を取得します。
    /// </summary>
    public required string GroupId { get; init; }
}

