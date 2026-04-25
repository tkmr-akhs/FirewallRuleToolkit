namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// import 直後の未解決セキュリティ ポリシー 1 件分の情報を保持します。
/// </summary>
public sealed class ImportedSecurityPolicy
{
    /// <summary>
    /// ポリシー インデックスを取得します。
    /// </summary>
    public ulong Index { get; init; }

    /// <summary>
    /// ポリシー名を取得します。
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// 送信元ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> FromZones { get; init; }

    /// <summary>
    /// 送信元アドレス参照一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> SourceAddressReferences { get; init; }

    /// <summary>
    /// 宛先ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> ToZones { get; init; }

    /// <summary>
    /// 宛先アドレス参照一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> DestinationAddressReferences { get; init; }

    /// <summary>
    /// アプリケーション一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> Applications { get; init; }

    /// <summary>
    /// サービス参照一覧を取得します。
    /// </summary>
    public required IReadOnlyList<string> ServiceReferences { get; init; }

    /// <summary>
    /// アクションを取得します。
    /// </summary>
    public SecurityPolicyAction Action { get; init; }

    /// <summary>
    /// グループ識別子を取得します。
    /// </summary>
    public required string GroupId { get; init; }
}
