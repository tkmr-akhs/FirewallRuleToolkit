using FirewallRuleToolkit.Domain.Services.Merging;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// Atomic ポリシー 1 件が merged 出力で表現されているかを判定します。
/// </summary>
internal sealed class SecurityPolicyTester
{
    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的にテストの過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// Atomic ポリシー 1 件が merged 出力で表現されているかを判定するクラスのコンストラクターです。
    /// </summary>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyTester(ILogger? logger = null)
    {
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 1 件の照合結果です。
    /// </summary>
    /// <param name="FindingKind">不一致の種別。完全一致時は <see langword="null"/>。</param>
    /// <param name="MatchedMergedPolicy">最初にヒットした merged。未ヒット時は <see langword="null"/>。</param>
    internal readonly record struct TestResult(
        SecurityPolicyTestRunner.FindingKind? FindingKind,
        MergedSecurityPolicy? MatchedMergedPolicy)
    {
        /// <summary>
        /// 照合が成功したかどうかを取得します。
        /// </summary>
        public bool IsMatch => FindingKind is null;
    }

    /// <summary>
    /// Atomic ポリシー 1 件を merged 列へ照合します。
    /// </summary>
    /// <param name="atomicPolicy">照合対象の Atomic ポリシー。</param>
    /// <param name="mergedPoliciesOrdered">`MinimumIndex`、`MaximumIndex` 順に並んだ merged ポリシー列。</param>
    /// <returns>照合結果。</returns>
    public TestResult Test(
        AtomicSecurityPolicy atomicPolicy,
        IReadOnlyList<MergedSecurityPolicy> mergedPoliciesOrdered)
    {
        ArgumentNullException.ThrowIfNull(atomicPolicy);
        ArgumentNullException.ThrowIfNull(mergedPoliciesOrdered);

        var matchedMergedPolicy = FindContainingMergedPolicy(atomicPolicy, mergedPoliciesOrdered);
        if (matchedMergedPolicy is null)
        {
            return new TestResult(SecurityPolicyTestRunner.FindingKind.MissingContainingMergedPolicy, null);
        }

        if (matchedMergedPolicy.Action != atomicPolicy.Action)
        {
            return new TestResult(SecurityPolicyTestRunner.FindingKind.ActionMismatch, matchedMergedPolicy);
        }

        return new TestResult(null, matchedMergedPolicy);
    }

    /// <summary>
    /// 最初に条件を満たした merged を返します。
    /// </summary>
    /// <param name="atomicPolicy">判定対象の Atomic ポリシー。</param>
    /// <param name="mergedPoliciesOrdered">ソート済み merged ポリシー列。</param>
    /// <returns>最初にヒットした merged。なければ <see langword="null"/>。</returns>
    private static MergedSecurityPolicy? FindContainingMergedPolicy(
        AtomicSecurityPolicy atomicPolicy,
        IReadOnlyList<MergedSecurityPolicy> mergedPoliciesOrdered)
    {
        foreach (var mergedPolicy in mergedPoliciesOrdered)
        {
            if (Contains(mergedPolicy, atomicPolicy))
            {
                return mergedPolicy;
            }
        }

        return null;
    }

    /// <summary>
    /// merged が Atomic を含むかを判定します。
    /// </summary>
    /// <param name="mergedPolicy">比較対象の merged。</param>
    /// <param name="atomicPolicy">比較対象の Atomic。</param>
    /// <returns>含むとき <see langword="true"/>。</returns>
    private static bool Contains(MergedSecurityPolicy mergedPolicy, AtomicSecurityPolicy atomicPolicy)
    {
        ArgumentNullException.ThrowIfNull(mergedPolicy);
        ArgumentNullException.ThrowIfNull(atomicPolicy);

        return mergedPolicy.FromZones.Contains(atomicPolicy.FromZone)
            && mergedPolicy.ToZones.Contains(atomicPolicy.ToZone)
            && mergedPolicy.SourceAddresses.Any(
                sourceAddress => EffectivePolicyConditionContainment.AddressCovers(
                    sourceAddress,
                    atomicPolicy.SourceAddress))
            && mergedPolicy.DestinationAddresses.Any(
                destinationAddress => EffectivePolicyConditionContainment.AddressCovers(
                    destinationAddress,
                    atomicPolicy.DestinationAddress))
            && mergedPolicy.Applications.Any(
                application => EffectivePolicyConditionContainment.ApplicationCovers(
                    application,
                    atomicPolicy.Application))
            && mergedPolicy.Services.Any(
                service => EffectivePolicyConditionContainment.ServiceCovers(
                    service,
                    atomicPolicy.Service));
    }
}
