namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge と test の内部処理で使う Atomic マージ候補を保持します。
/// </summary>
internal sealed class AtomicMergeCandidate
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
    public SecurityPolicyAction Action { get; init; }

    /// <summary>
    /// グループ識別子を取得します。
    /// </summary>
    public required string GroupId { get; init; }

    /// <summary>
    /// 最小インデックスを取得します。
    /// </summary>
    public ulong MinimumIndex { get; set; }

    /// <summary>
    /// 最大インデックスを取得します。
    /// </summary>
    public ulong MaximumIndex { get; set; }

    /// <summary>
    /// 元ポリシー名集合を取得します。
    /// </summary>
    public HashSet<string> OriginalPolicyNames { get; init; } = new();
}
