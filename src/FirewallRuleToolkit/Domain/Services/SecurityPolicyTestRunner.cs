using FirewallRuleToolkit.Domain.Services.Merging;
using FirewallRuleToolkit.Domain.Services.Results;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// merged 出力が Atomic ポリシーの挙動を保持しているかを検査するバッチ実行を提供します。
/// </summary>
internal sealed class SecurityPolicyTestRunner
{
    /// <summary>
    /// 進捗通知を行う Atomic ポリシー件数の間隔です。
    /// </summary>
    private const int ProgressReportInterval = 2000;

    private readonly SecurityPolicyTester tester;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的にテストの過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// merged 出力が Atomic ポリシーの挙動を保持しているかを検査するバッチ実行を提供するクラスのコンストラクターです。
    /// </summary>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyTestRunner(ILogger? logger = null)
        : this(new SecurityPolicyTester(logger), logger)
    {
    }

    /// <summary>
    /// テスト差し替え用の tester を受け取ってクラスを初期化します。
    /// </summary>
    /// <param name="tester">内部で利用するポリシー照合サービス。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    internal SecurityPolicyTestRunner(SecurityPolicyTester tester, ILogger? logger = null)
    {
        this.tester = tester ?? throw new ArgumentNullException(nameof(tester));
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 判定結果の種別です。
    /// </summary>
    public enum FindingKind
    {
        /// <summary>
        /// 含まれる merged が見つからなかったことを表します。
        /// </summary>
        MissingContainingMergedPolicy,

        /// <summary>
        /// 含まれる merged は見つかったが Action が一致しなかったことを表します。
        /// </summary>
        ActionMismatch
    }

    /// <summary>
    /// Atomic ポリシー 1 件に対する検査結果です。
    /// </summary>
    /// <param name="AtomicPolicy">検査対象の Atomic ポリシー。</param>
    /// <param name="IsShadowed">shadowed に分類された場合は <see langword="true"/>。</param>
    /// <param name="Kind">検査結果の種別。</param>
    /// <param name="MatchedMergedPolicy">最初にヒットした merged。未ヒット時は <see langword="null"/>。</param>
    public readonly record struct Finding(
        AtomicSecurityPolicy AtomicPolicy,
        bool IsShadowed,
        FindingKind Kind,
        MergedSecurityPolicy? MatchedMergedPolicy);

    /// <summary>
    /// merge 用順序の Atomic 列と merged 列を検査します。
    /// </summary>
    /// <param name="atomicPoliciesOrderedForMerge">merge 用順序の Atomic ポリシー列。</param>
    /// <param name="mergedPolicies">検査対象の merged ポリシー列。</param>
    /// <param name="reportFinding">不一致報告先。</param>
    /// <param name="reportProgress">進捗通知先。</param>
    /// <returns>検査結果の要約。</returns>
    public SecurityPolicyTestRunResult Run(
        IEnumerable<AtomicSecurityPolicy> atomicPoliciesOrderedForMerge,
        IEnumerable<MergedSecurityPolicy> mergedPolicies,
        Action<Finding>? reportFinding = null,
        Action<long>? reportProgress = null)
    {
        ArgumentNullException.ThrowIfNull(atomicPoliciesOrderedForMerge);
        ArgumentNullException.ThrowIfNull(mergedPolicies);

        reportFinding ??= static _ => { };

        var mergedPoliciesOrdered = mergedPolicies
            .OrderBy(static policy => policy.MinimumIndex)
            .ThenBy(static policy => policy.MaximumIndex)
            .ToArray();
        var classificationsOrderedByOriginalIndex = ClassifyAtomicPolicies(atomicPoliciesOrderedForMerge)
            .OrderBy(static classification => classification.Policy.OriginalIndex)
            .ToArray();

        long processedAtomicCount = 0;
        long nonShadowedAtomicCount = 0;
        long shadowedAtomicCount = 0;
        long warningCount = 0;
        long informationalCount = 0;

        foreach (var classification in classificationsOrderedByOriginalIndex)
        {
            processedAtomicCount++;
            if (processedAtomicCount % ProgressReportInterval == 0)
            {
                reportProgress?.Invoke(processedAtomicCount);
            }

            if (classification.IsShadowed)
            {
                shadowedAtomicCount++;
            }
            else
            {
                nonShadowedAtomicCount++;
            }

            var testResult = tester.Test(classification.Policy, mergedPoliciesOrdered);
            if (testResult.IsMatch)
            {
                continue;
            }

            reportFinding(new Finding(
                classification.Policy,
                classification.IsShadowed,
                testResult.FindingKind ?? throw new InvalidOperationException("Missing finding kind for mismatched result."),
                testResult.MatchedMergedPolicy));

            if (classification.IsShadowed)
            {
                informationalCount++;
            }
            else
            {
                warningCount++;
            }
        }

        return new SecurityPolicyTestRunResult
        {
            ProcessedAtomicCount = processedAtomicCount,
            NonShadowedAtomicCount = nonShadowedAtomicCount,
            ShadowedAtomicCount = shadowedAtomicCount,
            WarningCount = warningCount,
            InformationalCount = informationalCount
        };
    }

    /// <summary>
    /// Atomic 列を shadowed / 非 shadowed に分類します。
    /// </summary>
    /// <param name="atomicPoliciesOrderedForMerge">merge 用順序の Atomic ポリシー列。</param>
    /// <returns>分類結果。</returns>
    private static IEnumerable<AtomicPolicyClassification> ClassifyAtomicPolicies(
        IEnumerable<AtomicSecurityPolicy> atomicPoliciesOrderedForMerge)
    {
        var classifications = new List<AtomicPolicyClassification>();
        var partitionAtomicPolicies = new List<AtomicSecurityPolicy>();
        var partitionCandidates = new List<AtomicMergeCandidate>();
        MergePartitionKey? currentPartition = null;

        foreach (var atomicPolicy in atomicPoliciesOrderedForMerge)
        {
            var nextPartition = MergePartitionKey.FromAtomic(atomicPolicy);
            if (currentPartition is null)
            {
                currentPartition = nextPartition;
            }
            else if (!currentPartition.Value.Equals(nextPartition))
            {
                AppendPartitionClassifications(
                    classifications,
                    partitionAtomicPolicies,
                    partitionCandidates);
                currentPartition = nextPartition;
            }

            partitionAtomicPolicies.Add(atomicPolicy);
            partitionCandidates.Add(AtomicMergeCandidateFactory.CreateFromAtomic(atomicPolicy));
        }

        AppendPartitionClassifications(
            classifications,
            partitionAtomicPolicies,
            partitionCandidates);

        return classifications;
    }

    /// <summary>
    /// パーティション単位の shadow 分析結果を分類一覧へ追加します。
    /// </summary>
    /// <param name="destination">追加先。</param>
    /// <param name="partitionAtomicPolicies">対象パーティションの Atomic 列。</param>
    /// <param name="partitionCandidates">shadow 判定用の Atomic マージ候補列。</param>
    private static void AppendPartitionClassifications(
        List<AtomicPolicyClassification> destination,
        List<AtomicSecurityPolicy> partitionAtomicPolicies,
        List<AtomicMergeCandidate> partitionCandidates)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(partitionAtomicPolicies);
        ArgumentNullException.ThrowIfNull(partitionCandidates);

        if (partitionAtomicPolicies.Count == 0)
        {
            return;
        }

        var analysis = SecurityPolicyShadowAnalyzer.Analyze(partitionCandidates);
        var shadowedFlags = new bool[partitionAtomicPolicies.Count];
        foreach (var shadowingRelation in analysis.ShadowingRelations)
        {
            shadowedFlags[shadowingRelation.ShadowedIndex] = true;
        }

        for (var index = 0; index < partitionAtomicPolicies.Count; index++)
        {
            destination.Add(new AtomicPolicyClassification(partitionAtomicPolicies[index], shadowedFlags[index]));
        }

        partitionAtomicPolicies.Clear();
        partitionCandidates.Clear();
    }

    /// <summary>
    /// Atomic 1 件の shadow 分類結果です。
    /// </summary>
    /// <param name="Policy">対象 Atomic ポリシー。</param>
    /// <param name="IsShadowed">shadowed に分類された場合は <see langword="true"/>。</param>
    private readonly record struct AtomicPolicyClassification(
        AtomicSecurityPolicy Policy,
        bool IsShadowed);
}
