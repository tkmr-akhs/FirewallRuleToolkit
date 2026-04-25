namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// atomize サブコマンドの処理を提供します。
/// </summary>
internal static class AtomizeUseCase
{
    /// <summary>
    /// データベース内のルールを原子的な単位へ分解します。
    /// </summary>
    /// <param name="threshold">分解時のしきい値。</param>
    /// <param name="securityPolicyResolver">未解決ポリシーの解決処理。</param>
    /// <param name="sourceSecurityPolicies">入力ポリシー repository。</param>
    /// <param name="writeSession">出力先書き込みセッション。</param>
    /// <param name="reportProgress">入力ポリシー処理進捗の通知先。</param>
    /// <returns>終了コード。</returns>
    public static int Execute(
        int threshold,
        SecurityPolicyResolver securityPolicyResolver,
        IReadRepository<ImportedSecurityPolicy> sourceSecurityPolicies,
        IWriteRepositorySession writeSession,
        Action<int>? reportProgress = null)
    {
        ArgumentNullException.ThrowIfNull(securityPolicyResolver);
        ArgumentNullException.ThrowIfNull(sourceSecurityPolicies);
        ArgumentNullException.ThrowIfNull(writeSession);

        var logger = ProgramLogger.GetLogger(null, null, null);
        var runner = new SecurityPolicyAtomizeRunner(securityPolicyResolver, threshold, logger);
        reportProgress ??= processedCount =>
            logger.LogInformation("atomize progress. processed source policies: {ProcessedCount}", processedCount);

        sourceSecurityPolicies.EnsureAvailable();

        // 既存の atomize 結果は毎回作り直すため、先に出力先を初期化する。
        writeSession.AtomicPolicies.Initialize();

        runner.Run(
            sourceSecurityPolicies.GetAll(),
            writeSession.AtomicPolicies.AppendRange,
            reportProgress,
            skippedPolicy =>
                logger.LogWarning(
                    "atomize skipped policy. policy: {PolicyName}, index: {PolicyIndex}, reason: {Reason}",
                    skippedPolicy.PolicyName,
                    skippedPolicy.PolicyIndex,
                    skippedPolicy.Reason));

        writeSession.ToolMetadata.SetAtomizeThreshold(threshold);
        writeSession.Commit();
        return 0;
    }
}
