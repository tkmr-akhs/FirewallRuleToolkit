namespace FirewallRuleToolkit.Domain.Services.Results;

/// <summary>
/// merged 構築実行の結果要約です。
/// </summary>
internal sealed class SecurityPolicyMergeRunResult
{
    /// <summary>
    /// 処理した Atomic ポリシー件数を取得します。
    /// </summary>
    public long ProcessedAtomicCount { get; init; }

    /// <summary>
    /// 処理したパーティション件数を取得します。
    /// </summary>
    public long ProcessedPartitionCount { get; init; }

    /// <summary>
    /// 書き込んだ merged ポリシー件数を取得します。
    /// </summary>
    public long WrittenMergedCount { get; init; }

    /// <summary>
    /// アクション衝突の一覧を取得します。
    /// </summary>
    public IReadOnlyList<ActionRangeOverlap> ActionRangeOverlaps { get; init; } = [];

    /// <summary>
    /// 元インデックス範囲の要約です。
    /// </summary>
    public readonly record struct MergeIndexRange(
        SecurityPolicyAction Action,
        uint MinimumIndex,
        uint MaximumIndex);

    /// <summary>
    /// 異なるアクション間の衝突範囲です。
    /// </summary>
    public readonly record struct ActionRangeOverlap(
        MergeIndexRange Left,
        MergeIndexRange Right);
}
