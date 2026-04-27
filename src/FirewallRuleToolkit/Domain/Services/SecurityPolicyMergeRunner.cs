using FirewallRuleToolkit.Domain.Services.Merging;
using FirewallRuleToolkit.Domain.Services.Results;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// Atomic ポリシーから merged 出力を構築するバッチ実行を提供します。
/// </summary>
internal sealed class SecurityPolicyMergeRunner
{
    private readonly SecurityPolicyMerger merger;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的に集約の過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// Atomic ポリシーから merged 出力を構築するバッチ実行を提供するクラスのコンストラクターです。
    /// </summary>
    /// <param name="highSimilarityPercentThreshold">高一致率再編成に使う類似度しきい値 (パーセント)。</param>
    /// <param name="wellKnownDestinationPorts">宛先アドレス統合を抑止する対象ポート集合。</param>
    /// <param name="smallWellKnownDestinationPortCountThreshold">宛先アドレス統合を抑止する small well-known 宛先ポート数しきい値。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyMergeRunner(
        uint highSimilarityPercentThreshold,
        IReadOnlySet<uint>? wellKnownDestinationPorts,
        uint? smallWellKnownDestinationPortCountThreshold,
        ILogger? logger = null)
        : this(new SecurityPolicyMerger(
            highSimilarityPercentThreshold,
            wellKnownDestinationPorts,
            smallWellKnownDestinationPortCountThreshold,
            logger),
            logger)
    {
    }

    /// <summary>
    /// テスト差し替え用の merger を受け取ってクラスを初期化します。
    /// </summary>
    /// <param name="merger">内部で利用する統合サービス。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    internal SecurityPolicyMergeRunner(SecurityPolicyMerger merger, ILogger? logger = null)
    {
        this.merger = merger ?? throw new ArgumentNullException(nameof(merger));
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 入力ポリシー群を処理し、merged 出力を追記します。
    /// </summary>
    /// <remarks>
    /// このメソッドは入力列を並び替えず、同一 merge パーティションが連続しているかも検証しません。
    /// 同じパーティションが途中で分断されると別パーティションとして処理され、shadow 判定や merge 結果が変わります。
    /// </remarks>
    /// <param name="atomicPoliciesOrderedForMerge">`FromZone`、`ToZone`、`Service.Kind`、`OriginalIndex` の順で並び、同じ merge パーティションが連続するよう整列された Atomic ポリシー列。</param>
    /// <param name="emitMergedPolicies">生成した merged ポリシー batch の通知先。</param>
    /// <param name="onAtomicPolicyProcessed">Atomic ポリシー 1 件の処理完了通知先。</param>
    /// <returns>実行結果の要約。</returns>
    public SecurityPolicyMergeRunResult Run(
        IEnumerable<AtomicSecurityPolicy> atomicPoliciesOrderedForMerge,
        PolicyBatchEmitter<MergedSecurityPolicy> emitMergedPolicies,
        Action<long>? onAtomicPolicyProcessed = null)
    {
        ArgumentNullException.ThrowIfNull(atomicPoliciesOrderedForMerge);
        ArgumentNullException.ThrowIfNull(emitMergedPolicies);

        var partitionCandidates = new List<AtomicMergeCandidate>();
        var mergedRanges = new List<SecurityPolicyMergeRunResult.MergeIndexRange>();
        MergePartitionKey? currentPartition = null;

        var processedAtomicCount = 0L;
        var processedPartitionCount = 0L;
        var producedMergedCount = 0L;

        foreach (var atomicPolicy in atomicPoliciesOrderedForMerge)
        {
            processedAtomicCount++;
            onAtomicPolicyProcessed?.Invoke(processedAtomicCount);

            var nextPartition = MergePartitionKey.FromAtomic(atomicPolicy);
            if (currentPartition is null)
            {
                currentPartition = nextPartition;
            }
            else if (!currentPartition.Value.Equals(nextPartition))
            {
                var flushedPolicies = FlushPartitionAfterShadowing(partitionCandidates, emitMergedPolicies);
                producedMergedCount += flushedPolicies.Length;
                processedPartitionCount++;
                AppendMergeRanges(mergedRanges, flushedPolicies);
                currentPartition = nextPartition;
            }

            partitionCandidates.Add(AtomicMergeCandidateFactory.CreateFromAtomic(atomicPolicy));
        }

        if (partitionCandidates.Count > 0)
        {
            var flushedPolicies = FlushPartitionAfterShadowing(partitionCandidates, emitMergedPolicies);
            producedMergedCount += flushedPolicies.Length;
            processedPartitionCount++;
            AppendMergeRanges(mergedRanges, flushedPolicies);
        }

        return new SecurityPolicyMergeRunResult
        {
            ProcessedAtomicCount = processedAtomicCount,
            ProcessedPartitionCount = processedPartitionCount,
            ProducedMergedCount = producedMergedCount,
            ActionRangeOverlaps = FindActionRangeOverlaps(mergedRanges)
        };
    }

    /// <summary>
    /// 現在の partition から shadowed 候補を除去して merge し、生成した結果を通知します。
    /// </summary>
    /// <param name="partitionCandidates">対象 partition の Atomic マージ候補列。</param>
    /// <param name="emitMergedPolicies">生成した merged ポリシー batch の通知先。</param>
    /// <returns>生成した merged ポリシー列。</returns>
    private MergedSecurityPolicy[] FlushPartitionAfterShadowing(
        List<AtomicMergeCandidate> partitionCandidates,
        PolicyBatchEmitter<MergedSecurityPolicy> emitMergedPolicies)
    {
        if (partitionCandidates.Count == 0)
        {
            return [];
        }

        RemoveShadowedAtomicPolicies(partitionCandidates);

        var mergedPolicies = merger.MergePartition(partitionCandidates).ToArray();
        emitMergedPolicies(mergedPolicies);
        partitionCandidates.Clear();
        return mergedPolicies;
    }

    /// <summary>
    /// merged 化したポリシー群のインデックス範囲を衝突判定用バッファへ追加します。
    /// </summary>
    /// <param name="destination">追加先バッファ。</param>
    /// <param name="policies">追加対象の merged ポリシー列。</param>
    private static void AppendMergeRanges(
        List<SecurityPolicyMergeRunResult.MergeIndexRange> destination,
        IEnumerable<MergedSecurityPolicy> policies)
    {
        destination.AddRange(
            policies.Select(
                static policy => new SecurityPolicyMergeRunResult.MergeIndexRange(
                    policy.Action,
                    policy.MinimumIndex,
                    policy.MaximumIndex)));
    }

    /// <summary>
    /// 同一 merge partition 内で、先行ルールの背後に完全に隠れる後続ルールを取り除きます。
    /// </summary>
    /// <param name="partitionCandidates">対象 partition の Atomic マージ候補列。</param>
    private static void RemoveShadowedAtomicPolicies(List<AtomicMergeCandidate> partitionCandidates)
    {
        ArgumentNullException.ThrowIfNull(partitionCandidates);

        if (partitionCandidates.Count < 2)
        {
            return;
        }

        var analysis = SecurityPolicyShadowAnalyzer.Analyze(partitionCandidates);
        if (analysis.ShadowingRelations.Count == 0)
        {
            return;
        }

        var nonShadowedCandidates = analysis.NonShadowedIndices
            .Select(index => partitionCandidates[index])
            .ToList();

        var nonShadowedPositions = analysis.NonShadowedIndices
            .Select(
                static (originalIndex, nonShadowedIndex) => new
                {
                    OriginalIndex = originalIndex,
                    NonShadowedIndex = nonShadowedIndex
                })
            .ToDictionary(static item => item.OriginalIndex, static item => item.NonShadowedIndex);

        foreach (var shadowingRelation in analysis.ShadowingRelations)
        {
            var nonShadowedIndex = nonShadowedPositions[shadowingRelation.ShadowingIndex];
            nonShadowedCandidates[nonShadowedIndex] = AbsorbShadowedAtomicPolicy(
                nonShadowedCandidates[nonShadowedIndex],
                partitionCandidates[shadowingRelation.ShadowedIndex]);
        }

        partitionCandidates.Clear();
        partitionCandidates.AddRange(nonShadowedCandidates);
    }

    /// <summary>
    /// shadowed な後続候補のトレース情報を、前方候補側へ吸収した新しい候補を返します。
    /// </summary>
    /// <param name="frontPolicy">生存側の前方候補。</param>
    /// <param name="shadowedPolicy">吸収される後続候補。</param>
    /// <returns>トレース情報を統合した候補。</returns>
    private static AtomicMergeCandidate AbsorbShadowedAtomicPolicy(
        AtomicMergeCandidate frontPolicy,
        AtomicMergeCandidate shadowedPolicy)
    {
        ArgumentNullException.ThrowIfNull(frontPolicy);
        ArgumentNullException.ThrowIfNull(shadowedPolicy);

        var originalPolicyNames = new HashSet<string>(frontPolicy.OriginalPolicyNames, StringComparer.Ordinal);
        originalPolicyNames.UnionWith(shadowedPolicy.OriginalPolicyNames);

        return new AtomicMergeCandidate
        {
            FromZone = frontPolicy.FromZone,
            SourceAddress = frontPolicy.SourceAddress,
            ToZone = frontPolicy.ToZone,
            DestinationAddress = frontPolicy.DestinationAddress,
            Application = frontPolicy.Application,
            Service = frontPolicy.Service,
            Action = frontPolicy.Action,
            GroupId = frontPolicy.GroupId,
            MinimumIndex = Math.Min(frontPolicy.MinimumIndex, shadowedPolicy.MinimumIndex),
            MaximumIndex = Math.Max(frontPolicy.MaximumIndex, shadowedPolicy.MaximumIndex),
            OriginalPolicyNames = originalPolicyNames
        };
    }

    /// <summary>
    /// 異なるアクション間で元インデックス範囲が衝突している組を列挙します。
    /// </summary>
    /// <param name="ranges">判定対象のインデックス範囲列。</param>
    /// <returns>衝突している範囲の組一覧。</returns>
    internal static IReadOnlyList<SecurityPolicyMergeRunResult.ActionRangeOverlap> FindActionRangeOverlaps(
        IReadOnlyList<SecurityPolicyMergeRunResult.MergeIndexRange> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);

        var rangesOrderedByStart = ranges
            .OrderBy(static range => range.MinimumIndex)
            .ThenBy(static range => range.MaximumIndex)
            .ToArray();

        var overlaps = new List<SecurityPolicyMergeRunResult.ActionRangeOverlap>();
        var openRanges = new List<SecurityPolicyMergeRunResult.MergeIndexRange>();

        foreach (var currentRange in rangesOrderedByStart)
        {
            var currentStart = currentRange.MinimumIndex;
            openRanges.RemoveAll(openRange => openRange.MaximumIndex < currentStart);

            foreach (var openRange in openRanges)
            {
                if (openRange.Action == currentRange.Action)
                {
                    continue;
                }

                overlaps.Add(new SecurityPolicyMergeRunResult.ActionRangeOverlap(openRange, currentRange));
            }

            openRanges.Add(currentRange);
        }

        return overlaps;
    }
}
