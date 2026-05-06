using FirewallRuleToolkit.Domain.Services.Merging;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// Atomic ポリシーの部分集合を統合します。
/// </summary>
internal sealed class SecurityPolicyMerger
{
    /// <summary>
    /// サービスだけが異なるポリシーを統合します。
    /// </summary>
    private readonly ServiceMerger serviceMerger;

    /// <summary>
    /// 送信元アドレスだけが異なるポリシーを統合します。
    /// </summary>
    private readonly SourceAddressMerger sourceAddressMerger;

    /// <summary>
    /// 宛先アドレスだけが異なるポリシーを統合します。
    /// </summary>
    private readonly DestinationAddressMerger destinationAddressMerger;

    /// <summary>
    /// 同じ元ルール由来の非 Allow ポリシーを統合します。
    /// </summary>
    private readonly OriginalRuleMerger originalRuleMerger;

    /// <summary>
    /// 高一致率の merged ポリシーを共通部と残差へ再編成します。
    /// </summary>
    private readonly HighSimilarityPolicyRecomposer highSimilarityPolicyRecomposer;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的に集約の過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// Atomic ポリシーの部分集合を統合するクラスのコンストラクターです。
    /// </summary>
    /// <param name="highSimilarityPercentThreshold">高一致率再編成に使う類似度しきい値 (パーセント)。</param>
    /// <param name="wellKnownDestinationPorts">宛先アドレス分離判定に使う既知ポート集合。</param>
    /// <param name="smallWellKnownDestinationPortCountThreshold">宛先アドレス分離を維持する small well-known 宛先ポート数しきい値。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyMerger(
        uint highSimilarityPercentThreshold,
        IReadOnlySet<uint>? wellKnownDestinationPorts = null,
        uint? smallWellKnownDestinationPortCountThreshold = null,
        ILogger? logger = null)
    {
        var smallWellKnownDestinationPortMatcher = new SmallWellKnownDestinationPortMatcher(
            wellKnownDestinationPorts,
            smallWellKnownDestinationPortCountThreshold);

        this.logger = logger.OrNullLogger();
        serviceMerger = new ServiceMerger();
        sourceAddressMerger = new SourceAddressMerger();
        destinationAddressMerger = new DestinationAddressMerger(smallWellKnownDestinationPortMatcher, this.logger);
        originalRuleMerger = new OriginalRuleMerger();
        highSimilarityPolicyRecomposer = new HighSimilarityPolicyRecomposer(
            smallWellKnownDestinationPortMatcher,
            highSimilarityPercentThreshold,
            this.logger);
    }

    /// <summary>
    /// 同一 merge パーティション内の Atomic マージ候補を統合します。
    /// </summary>
    /// <param name="partitionPolicies">統合対象の Atomic マージ候補列。</param>
    /// <returns>統合済みポリシー列。</returns>
    public IReadOnlyList<MergedSecurityPolicy> MergePartition(IReadOnlyList<AtomicMergeCandidate> partitionPolicies)
    {
        // partition 分割は runner で行っており、このメソッドは runner.FlushPartition から呼ばれる。
        // MergePartitionKey が同一のものを 1 partition として扱う。

        ArgumentNullException.ThrowIfNull(partitionPolicies);
        if (partitionPolicies.Count == 0)
        {
            return [];
        }

        // 集約結果用のリスト
        var merged = new List<MutableMergedSecurityPolicy>();

        // Allow ポリシーの処理
        var allowPolicies = partitionPolicies
            .Where(static policy => policy.Action == SecurityPolicyAction.Allow)
            .ToArray();
        if (allowPolicies.Length > 0)
        {
            merged.AddRange(MergeAllowPolicies(allowPolicies));
        }

        // 非 Allow ポリシーの処理
        var nonAllowPolicies = partitionPolicies
            .Where(static policy => policy.Action != SecurityPolicyAction.Allow)
            .ToArray();
        if (nonAllowPolicies.Length > 0)
        {
            merged.AddRange(MergeNonAllowPolicies(nonAllowPolicies));
        }

        // 結果の返却
        return merged
            .OrderBy(static policy => policy.MinimumIndex)
            .ThenBy(static policy => policy.MaximumIndex)
            .Select(static policy => policy.ToMergedSecurityPolicy())
            .ToArray();
    }

    /// <summary>
    /// Allow Atomic ポリシー群を通常の統合ルールで集約します。
    /// </summary>
    /// <param name="partitionPolicies">Allow のみから成る統合対象。</param>
    /// <returns>統合済みポリシー列。</returns>
    private List<MutableMergedSecurityPolicy> MergeAllowPolicies(IReadOnlyList<AtomicMergeCandidate> partitionPolicies)
    {
        // atomic の状態で、重複を除去する。
        var deduplicated = AtomicMergeCandidateDeduplicator.RemoveContainedPolicies(partitionPolicies);

        // atomic を「各要素が 1 個だけ入った Merged」に変換し、
        // 以降の集約処理の中で各集合に集約対象の要素を吸収していく。
        var merged = deduplicated
            .Select(MergedSecurityPolicyFactory.CreateFromAtomic)
            .ToList();

        // サービスのみが異なるルールを集約する。
        merged = serviceMerger.Merge(merged);

        // 送信元アドレスのみが異なるルールを集約する。
        merged = sourceAddressMerger.Merge(merged);

        // 宛先アドレスのみが異なるルールを集約する。
        // (ただし、ここだけ特殊で、サービスの宛先ポートがよく使われるもののみ、かつ、数が少ないときは、集約しない)
        merged = destinationAddressMerger.Merge(merged);

        // 3 パス完了後に、高一致率な複数軸差分を共通部と残差へ再編成する。
        return [.. highSimilarityPolicyRecomposer.RecomposeMutable(merged)];
    }

    /// <summary>
    /// 非 Allow Atomic ポリシー群を、同じ元ルール由来のものだけ束ねて返します。
    /// </summary>
    /// <param name="partitionPolicies">非 Allow のみから成る統合対象。</param>
    /// <returns>同一元ルール単位で束ねた merged ポリシー列。</returns>
    private List<MutableMergedSecurityPolicy> MergeNonAllowPolicies(IReadOnlyList<AtomicMergeCandidate> partitionPolicies)
    {
        return originalRuleMerger.Merge(partitionPolicies.Select(MergedSecurityPolicyFactory.CreateFromAtomic));
    }
}
