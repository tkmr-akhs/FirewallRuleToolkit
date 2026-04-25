using FirewallRuleToolkit.Domain.Services.Results;

namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// セキュリティ ポリシー群から atomic 出力を構築するバッチ実行を提供します。
/// </summary>
internal sealed class SecurityPolicyAtomizeRunner
{
    /// <summary>
    /// 進捗通知を行う入力ポリシー件数の間隔です。
    /// </summary>
    private const int ProgressReportInterval = 200;

    private readonly SecurityPolicyResolver securityPolicyResolver;
    private readonly SecurityPolicyAtomizer atomizer;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的に分解の過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

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
    /// <param name="appendAtomicPolicies">atomic ポリシーの追記先。</param>
    /// <param name="reportProgress">入力ポリシー処理進捗の通知先。</param>
    /// <param name="reportSkippedPolicy">スキップした入力ポリシーの通知先。</param>
    /// <returns>実行結果の要約。</returns>
    public SecurityPolicyAtomizeRunResult Run(
        IEnumerable<ImportedSecurityPolicy> importedSecurityPolicies,
        Action<IEnumerable<AtomicSecurityPolicy>> appendAtomicPolicies,
        Action<int>? reportProgress = null,
        Action<SkippedPolicy>? reportSkippedPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(importedSecurityPolicies);
        ArgumentNullException.ThrowIfNull(appendAtomicPolicies);

        var processedSourcePolicyCount = 0;
        var skippedSourcePolicyCount = 0;

        foreach (var importedPolicy in importedSecurityPolicies)
        {
            processedSourcePolicyCount++;

            AtomicSecurityPolicy[] atomizedPolicies;
            var shouldAppend = true;
            try
            {
                var resolvedPolicy = securityPolicyResolver.Resolve(importedPolicy);
                atomizedPolicies = atomizer.Atomize(resolvedPolicy).ToArray();
            }
            catch (FormatException ex)
            {
                skippedSourcePolicyCount++;
                reportSkippedPolicy?.Invoke(new SkippedPolicy(importedPolicy.Name, importedPolicy.Index, ex.Message));
                atomizedPolicies = [];
                shouldAppend = false;
            }
            catch (InvalidOperationException ex)
            {
                skippedSourcePolicyCount++;
                reportSkippedPolicy?.Invoke(new SkippedPolicy(importedPolicy.Name, importedPolicy.Index, ex.Message));
                atomizedPolicies = [];
                shouldAppend = false;
            }

            if (shouldAppend)
            {
                appendAtomicPolicies(atomizedPolicies);
            }

            if (processedSourcePolicyCount % ProgressReportInterval == 0)
            {
                reportProgress?.Invoke(processedSourcePolicyCount);
            }
        }

        return new SecurityPolicyAtomizeRunResult
        {
            ProcessedSourcePolicyCount = processedSourcePolicyCount,
            SkippedSourcePolicyCount = skippedSourcePolicyCount
        };
    }

    /// <summary>
    /// スキップした入力ポリシーの情報です。
    /// </summary>
    /// <param name="PolicyName">ポリシー名。</param>
    /// <param name="PolicyIndex">元ポリシー インデックス。</param>
    /// <param name="Reason">スキップ理由。</param>
    public readonly record struct SkippedPolicy(
        string PolicyName,
        ulong PolicyIndex,
        string Reason);
}
