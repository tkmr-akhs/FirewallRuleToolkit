namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// test サブコマンドの処理を提供します。
/// </summary>
internal static class TestUseCase
{
    /// <summary>
    /// merged 出力が Atomic ポリシーの挙動を保持しているかを検査します。
    /// </summary>
    /// <param name="sourceAtomicPolicies">merge 用順序で Atomic ポリシーを提供する repository。</param>
    /// <param name="sourceMergedPolicies">比較対象の merged ポリシー repository。</param>
    /// <param name="reportProgress">進捗通知先。</param>
    /// <returns>終了コード。</returns>
    public static int Execute(
        IAtomicPolicyMergeSource sourceAtomicPolicies,
        IReadRepository<MergedSecurityPolicy> sourceMergedPolicies,
        Action<long>? reportProgress = null)
    {
        ArgumentNullException.ThrowIfNull(sourceAtomicPolicies);
        ArgumentNullException.ThrowIfNull(sourceMergedPolicies);

        var logger = ProgramLogger.GetLogger(null, null, null);
        var runner = new SecurityPolicyTestRunner(logger);
        reportProgress ??= processedAtomicCount =>
            logger.LogInformation("test progress. processed atomic policies: {ProcessedAtomicCount}", processedAtomicCount);

        sourceAtomicPolicies.EnsureAvailable();
        sourceMergedPolicies.EnsureAvailable();

        logger.LogInformation("test started.");

        var result = runner.Run(
            sourceAtomicPolicies.GetAllOrderedForMerge(),
            sourceMergedPolicies.GetAll(),
            finding => LogFinding(logger, finding),
            reportProgress);

        logger.LogInformation(
            "test completed. atomicProcessed: {AtomicProcessed}, nonShadowedChecked: {NonShadowedChecked}, shadowedChecked: {ShadowedChecked}, warnings: {WarningCount}, informationals: {InformationalCount}",
            result.ProcessedAtomicCount,
            result.NonShadowedAtomicCount,
            result.ShadowedAtomicCount,
            result.WarningCount,
            result.InformationalCount);

        return 0;
    }

    /// <summary>
    /// 検査結果 1 件をログへ出力します。
    /// </summary>
    /// <param name="logger">出力先ロガー。</param>
    /// <param name="finding">出力対象の検査結果。</param>
    private static void LogFinding(
        ILogger logger,
        SecurityPolicyTestRunner.Finding finding)
    {
        ArgumentNullException.ThrowIfNull(logger);

        if (finding.Kind == SecurityPolicyTestRunner.FindingKind.ActionMismatch)
        {
            LogActionMismatch(logger, finding);
            return;
        }

        LogMissingContainingMergedPolicy(logger, finding);
    }

    /// <summary>
    /// 含まれる merged が見つからなかった結果をログへ出力します。
    /// </summary>
    /// <param name="logger">出力先ロガー。</param>
    /// <param name="finding">出力対象の検査結果。</param>
    private static void LogMissingContainingMergedPolicy(
        ILogger logger,
        SecurityPolicyTestRunner.Finding finding)
    {
        var atomicPolicy = finding.AtomicPolicy;
        if (finding.IsShadowed)
        {
            logger.LogInformation(
                "test info: shadowed atomic policy is not directly represented in merged output. policy={PolicyName}, index={PolicyIndex}, action={AtomicAction}, fromZone={FromZone}, toZone={ToZone}, application={Application}",
                atomicPolicy.OriginalPolicyName,
                atomicPolicy.OriginalIndex,
                atomicPolicy.Action,
                atomicPolicy.FromZone,
                atomicPolicy.ToZone,
                atomicPolicy.Application);
            return;
        }

        logger.LogWarning(
            "test warning: atomic policy is not represented in merged output. policy={PolicyName}, index={PolicyIndex}, action={AtomicAction}, fromZone={FromZone}, toZone={ToZone}, application={Application}",
            atomicPolicy.OriginalPolicyName,
            atomicPolicy.OriginalIndex,
            atomicPolicy.Action,
            atomicPolicy.FromZone,
            atomicPolicy.ToZone,
            atomicPolicy.Application);
    }

    /// <summary>
    /// 含まれる merged と Action が一致しなかった結果をログへ出力します。
    /// </summary>
    /// <param name="logger">出力先ロガー。</param>
    /// <param name="finding">出力対象の検査結果。</param>
    private static void LogActionMismatch(
        ILogger logger,
        SecurityPolicyTestRunner.Finding finding)
    {
        var atomicPolicy = finding.AtomicPolicy;
        var matchedMergedPolicy = finding.MatchedMergedPolicy
            ?? throw new InvalidOperationException("Action mismatch finding must have matched merged policy.");

        if (finding.IsShadowed)
        {
            logger.LogInformation(
                "test info: shadowed atomic policy matched merged output but action differed. policy={PolicyName}, index={PolicyIndex}, atomicAction={AtomicAction}, mergedAction={MergedAction}, mergedRange=[{MergedMinimumIndex}-{MergedMaximumIndex}], fromZone={FromZone}, toZone={ToZone}, application={Application}",
                atomicPolicy.OriginalPolicyName,
                atomicPolicy.OriginalIndex,
                atomicPolicy.Action,
                matchedMergedPolicy.Action,
                matchedMergedPolicy.MinimumIndex,
                matchedMergedPolicy.MaximumIndex,
                atomicPolicy.FromZone,
                atomicPolicy.ToZone,
                atomicPolicy.Application);
            return;
        }

        logger.LogWarning(
            "test warning: atomic policy matched merged output but action differed. policy={PolicyName}, index={PolicyIndex}, atomicAction={AtomicAction}, mergedAction={MergedAction}, mergedRange=[{MergedMinimumIndex}-{MergedMaximumIndex}], fromZone={FromZone}, toZone={ToZone}, application={Application}",
            atomicPolicy.OriginalPolicyName,
            atomicPolicy.OriginalIndex,
            atomicPolicy.Action,
            matchedMergedPolicy.Action,
            matchedMergedPolicy.MinimumIndex,
            matchedMergedPolicy.MaximumIndex,
            atomicPolicy.FromZone,
            atomicPolicy.ToZone,
            atomicPolicy.Application);
    }
}
