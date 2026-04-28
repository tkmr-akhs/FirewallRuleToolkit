using FirewallRuleToolkit.Domain.Services.Merging;
using FirewallRuleToolkit.Domain.Services.Results;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// merged 出力が Atomic ポリシーの挙動を保持しているかを検査するバッチ実行を提供します。
/// </summary>
internal sealed class SecurityPolicyTestRunner
{
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
    /// 検査結果の診断重要度です。
    /// </summary>
    public enum DiagnosticSeverity
    {
        /// <summary>
        /// 情報として扱う診断を表します。
        /// </summary>
        Informational,

        /// <summary>
        /// 警告として扱う診断を表します。
        /// </summary>
        Warning
    }

    /// <summary>
    /// Atomic ポリシー 1 件に対する検査結果です。
    /// </summary>
    /// <param name="AtomicPolicy">検査対象の Atomic ポリシー。</param>
    /// <param name="IsShadowed">shadowed に分類された場合は <see langword="true"/>。</param>
    /// <param name="Severity">診断重要度。</param>
    /// <param name="Kind">検査結果の種別。</param>
    /// <param name="MatchedMergedPolicy">最初にヒットした merged。未ヒット時は <see langword="null"/>。</param>
    public readonly record struct Finding(
        AtomicSecurityPolicy AtomicPolicy,
        bool IsShadowed,
        DiagnosticSeverity Severity,
        FindingKind Kind,
        MergedSecurityPolicy? MatchedMergedPolicy);

    /// <summary>
    /// merge 用順序の Atomic 列と merged 列を検査します。
    /// </summary>
    /// <remarks>
    /// shadowed 分類は merge と同じパーティション前提で行うため、入力列は同一 merge パーティションが連続する順序である必要があります。
    /// このメソッドは入力列を並び替えず、順序契約違反も検出しません。
    /// </remarks>
    /// <param name="atomicPoliciesOrderedForMerge">merge 用順序で並び、同じ merge パーティションが連続するよう整列された Atomic ポリシー列。</param>
    /// <param name="mergedPolicies">first-hit 検証順で並んだ merged ポリシー列。</param>
    /// <param name="reportFinding">不一致報告先。</param>
    /// <param name="onAtomicPolicyProcessed">Atomic ポリシー 1 件の処理完了通知先。</param>
    /// <returns>検査結果の要約。</returns>
    public SecurityPolicyTestRunResult Run(
        IEnumerable<AtomicSecurityPolicy> atomicPoliciesOrderedForMerge,
        IEnumerable<MergedSecurityPolicy> mergedPolicies,
        Action<Finding>? reportFinding = null,
        Action<long>? onAtomicPolicyProcessed = null)
    {
        ArgumentNullException.ThrowIfNull(atomicPoliciesOrderedForMerge);
        ArgumentNullException.ThrowIfNull(mergedPolicies);

        reportFinding ??= static _ => { };

        var mergedPoliciesOrdered = mergedPolicies.ToArray();

        long processedAtomicCount = 0;
        long nonShadowedAtomicCount = 0;
        long shadowedAtomicCount = 0;
        long warningDiagnosticCount = 0;
        long informationalDiagnosticCount = 0;

        foreach (var classification in ClassifyAtomicPolicies(atomicPoliciesOrderedForMerge))
        {
            processedAtomicCount++;
            onAtomicPolicyProcessed?.Invoke(processedAtomicCount);

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

            var severity = classification.IsShadowed
                ? DiagnosticSeverity.Informational
                : DiagnosticSeverity.Warning;

            reportFinding(new Finding(
                classification.Policy,
                classification.IsShadowed,
                severity,
                testResult.FindingKind ?? throw new InvalidOperationException("Missing finding kind for mismatched result."),
                testResult.MatchedMergedPolicy));

            if (severity == DiagnosticSeverity.Informational)
            {
                informationalDiagnosticCount++;
            }
            else
            {
                warningDiagnosticCount++;
            }
        }

        return new SecurityPolicyTestRunResult
        {
            ProcessedAtomicCount = processedAtomicCount,
            NonShadowedAtomicCount = nonShadowedAtomicCount,
            ShadowedAtomicCount = shadowedAtomicCount,
            WarningDiagnosticCount = warningDiagnosticCount,
            InformationalDiagnosticCount = informationalDiagnosticCount
        };
    }

    /// <summary>
    /// Atomic 列を shadowed / 非 shadowed に分類します。
    /// </summary>
    /// <param name="atomicPoliciesOrderedForMerge">merge 用順序で並び、同じ merge パーティションが連続するよう整列された Atomic ポリシー列。</param>
    /// <returns>分類結果。</returns>
    private static IEnumerable<AtomicPolicyClassification> ClassifyAtomicPolicies(
        IEnumerable<AtomicSecurityPolicy> atomicPoliciesOrderedForMerge)
    {
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
                foreach (var classification in ClassifyPartition(
                    partitionAtomicPolicies,
                    partitionCandidates))
                {
                    yield return classification;
                }

                partitionAtomicPolicies.Clear();
                partitionCandidates.Clear();
                currentPartition = nextPartition;
            }

            partitionAtomicPolicies.Add(atomicPolicy);
            partitionCandidates.Add(AtomicMergeCandidateFactory.CreateFromAtomic(atomicPolicy));
        }

        foreach (var classification in ClassifyPartition(
            partitionAtomicPolicies,
            partitionCandidates))
        {
            yield return classification;
        }
    }

    /// <summary>
    /// パーティション単位の shadow 分析結果を分類列へ変換します。
    /// </summary>
    /// <param name="partitionAtomicPolicies">対象パーティションの Atomic 列。</param>
    /// <param name="partitionCandidates">shadow 判定用の Atomic マージ候補列。</param>
    /// <returns>分類結果。</returns>
    private static IEnumerable<AtomicPolicyClassification> ClassifyPartition(
        List<AtomicSecurityPolicy> partitionAtomicPolicies,
        List<AtomicMergeCandidate> partitionCandidates)
    {
        ArgumentNullException.ThrowIfNull(partitionAtomicPolicies);
        ArgumentNullException.ThrowIfNull(partitionCandidates);

        if (partitionAtomicPolicies.Count == 0)
        {
            yield break;
        }

        var analysis = SecurityPolicyShadowAnalyzer.Analyze(partitionCandidates);
        var shadowedFlags = new bool[partitionAtomicPolicies.Count];
        foreach (var shadowingRelation in analysis.ShadowingRelations)
        {
            shadowedFlags[shadowingRelation.ShadowedIndex] = true;
        }

        for (var index = 0; index < partitionAtomicPolicies.Count; index++)
        {
            yield return new AtomicPolicyClassification(partitionAtomicPolicies[index], shadowedFlags[index]);
        }
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
