using FirewallRuleToolkit.Domain.Services.Results;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// セキュリティ ポリシー群から atomic 出力を構築するバッチ実行を提供します。
/// </summary>
public sealed class SecurityPolicyAtomizeRunner
{
    private readonly SecurityPolicyResolver securityPolicyResolver;
    private readonly SecurityPolicyAtomizer atomizer;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的に分解の過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// atomic 化できずにスキップした入力ポリシーの情報です。
    /// </summary>
    /// <param name="PolicyName">スキップした入力ポリシー名。</param>
    /// <param name="PolicyIndex">スキップした入力ポリシーの元インデックス。</param>
    /// <param name="Reason">スキップ理由。</param>
    public readonly record struct SkippedPolicy(
        string PolicyName,
        uint PolicyIndex,
        string Reason);

    /// <summary>
    /// サービス参照が Kind 指定へフォールバックした情報です。
    /// </summary>
    /// <param name="PolicyName">フォールバックが発生した入力ポリシー名。</param>
    /// <param name="PolicyIndex">フォールバックが発生した入力ポリシーの元インデックス。</param>
    /// <param name="ServiceReference">Kind 指定へフォールバックしたサービス参照。</param>
    public readonly record struct ServiceReferenceKindFallback(
        string? PolicyName,
        uint? PolicyIndex,
        string ServiceReference);

    /// <summary>
    /// セキュリティ ポリシー群から atomic 出力を構築するバッチ実行を提供するクラスのコンストラクターです。
    /// </summary>
    /// <param name="securityPolicyResolver">未解決ポリシーの解決処理。</param>
    /// <param name="threshold">範囲を単一値へ分解するしきい値。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyAtomizeRunner(
        SecurityPolicyResolver securityPolicyResolver,
        int threshold,
        ILogger? logger = null)
        : this(securityPolicyResolver, new SecurityPolicyAtomizer(threshold, logger), logger)
    {
    }

    /// <summary>
    /// テスト差し替え用の atomizer を受け取ってクラスを初期化します。
    /// </summary>
    /// <param name="securityPolicyResolver">未解決ポリシーの解決処理。</param>
    /// <param name="atomizer">内部で利用する分解サービス。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    internal SecurityPolicyAtomizeRunner(
        SecurityPolicyResolver securityPolicyResolver,
        SecurityPolicyAtomizer atomizer,
        ILogger? logger = null)
    {
        this.securityPolicyResolver = securityPolicyResolver ?? throw new ArgumentNullException(nameof(securityPolicyResolver));
        this.atomizer = atomizer ?? throw new ArgumentNullException(nameof(atomizer));
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 入力ポリシー群を処理し、atomic 出力を追記します。
    /// </summary>
    /// <param name="importedSecurityPolicies">分解対象の入力ポリシー列。</param>
    /// <param name="emitAtomicPolicies">生成した atomic ポリシー batch の通知先。</param>
    /// <param name="onSourcePolicyProcessed">入力ポリシー 1 件の処理完了通知先。</param>
    /// <param name="reportSkippedPolicy">スキップした入力ポリシーの通知先。</param>
    /// <param name="reportServiceReferenceKindFallback">サービス参照が Kind 指定へフォールバックしたことの通知先。</param>
    /// <returns>実行結果の要約。</returns>
    public SecurityPolicyAtomizeRunResult Run(
        IEnumerable<ImportedSecurityPolicy> importedSecurityPolicies,
        PolicyBatchEmitter<AtomicSecurityPolicy> emitAtomicPolicies,
        Action<int>? onSourcePolicyProcessed = null,
        Action<SkippedPolicy>? reportSkippedPolicy = null,
        Action<ServiceReferenceKindFallback>? reportServiceReferenceKindFallback = null)
    {
        ArgumentNullException.ThrowIfNull(importedSecurityPolicies);
        ArgumentNullException.ThrowIfNull(emitAtomicPolicies);

        var processedSourcePolicyCount = 0;
        var skippedSourcePolicyCount = 0;

        void ReportServiceReferenceKindFallback(
            string? policyName,
            uint? policyIndex,
            string serviceReference)
        {
            reportServiceReferenceKindFallback?.Invoke(new ServiceReferenceKindFallback(
                policyName,
                policyIndex,
                serviceReference));
        }

        securityPolicyResolver.ServiceReferenceKindFallbackOccurred += ReportServiceReferenceKindFallback;
        try
        {
            foreach (var importedPolicy in importedSecurityPolicies)
            {
                processedSourcePolicyCount++;

                try
                {
                    var resolvedPolicy = securityPolicyResolver.Resolve(importedPolicy);
                    var atomizedPolicies = atomizer.Atomize(resolvedPolicy).ToArray();
                    emitAtomicPolicies(atomizedPolicies);
                }
                catch (UnsupportedAddressPolicyException exception)
                {
                    skippedSourcePolicyCount++;
                    var reason = exception.InnerException?.Message ?? exception.Message;
                    reportSkippedPolicy?.Invoke(new SkippedPolicy(
                        importedPolicy.Name,
                        importedPolicy.Index,
                        reason));
                }

                onSourcePolicyProcessed?.Invoke(processedSourcePolicyCount);
            }
        }
        finally
        {
            securityPolicyResolver.ServiceReferenceKindFallbackOccurred -= ReportServiceReferenceKindFallback;
        }

        return new SecurityPolicyAtomizeRunResult
        {
            ProcessedSourcePolicyCount = processedSourcePolicyCount,
            SkippedSourcePolicyCount = skippedSourcePolicyCount
        };
    }

}
