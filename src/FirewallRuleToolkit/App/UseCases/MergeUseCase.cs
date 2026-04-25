namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// merge サブコマンドの処理を提供します。
/// </summary>
internal static class MergeUseCase
{
    /// <summary>
    /// データベース内の Atomic ポリシーを統合します。
    /// </summary>
    /// <param name="sourceAtomicPolicies">merge 用順序で Atomic ポリシーを提供する repository。</param>
    /// <param name="writeSession">出力先書き込みセッション。</param>
    /// <param name="wellKnownDestinationPorts">宛先アドレス集約抑止に使う既知ポート集合。</param>
    /// <param name="smallWellKnownDestinationPortCountThreshold">宛先アドレス集約抑止に使う small well-known 宛先ポート数しきい値。</param>
    /// <param name="highSimilarityPercentThreshold">高一致率再編成に使う類似度しきい値 (パーセント)。</param>
    /// <param name="reportProgress">進捗通知先。</param>
    /// <returns>終了コード。</returns>
    public static int Execute(
        IAtomicPolicyMergeSource sourceAtomicPolicies,
        IWriteRepositorySession writeSession,
        uint highSimilarityPercentThreshold,
        IReadOnlySet<uint>? wellKnownDestinationPorts = null,
        uint? smallWellKnownDestinationPortCountThreshold = null,
        Action<long>? reportProgress = null)
    {
        ArgumentNullException.ThrowIfNull(sourceAtomicPolicies);
        ArgumentNullException.ThrowIfNull(writeSession);

        var logger = ProgramLogger.GetLogger(null, null, null);
        var runner = new SecurityPolicyMergeRunner(
            highSimilarityPercentThreshold,
            wellKnownDestinationPorts,
            smallWellKnownDestinationPortCountThreshold,
            logger);
        reportProgress ??= processedAtomicCount =>
            logger.LogInformation("merge progress. processed atomic policies: {ProcessedAtomicCount}", processedAtomicCount);

        sourceAtomicPolicies.EnsureAvailable();

        // merged 出力は毎回フルリビルドするため、既存内容を先に空にする。
        writeSession.MergedSecurityPolicies.Initialize();
        logger.LogInformation("merge started.");

        var result = runner.Run(
            sourceAtomicPolicies.GetAllOrderedForMerge(),
            writeSession.MergedSecurityPolicies.AppendRange,
            reportProgress);

        logger.LogInformation(
            "merge completed. atomicProcessed: {AtomicProcessed}, partitionsProcessed: {PartitionsProcessed}, mergedWritten: {MergedWritten}",
            result.ProcessedAtomicCount,
            result.ProcessedPartitionCount,
            result.WrittenMergedCount);

        LogActionRangeOverlaps(logger, result.ActionRangeOverlaps);

        writeSession.Commit();
        return 0;
    }

    /// <summary>
    /// 異なるアクション同士で元インデックス範囲が重複した組を警告ログへ出力します。
    /// </summary>
    /// <param name="logger">出力先ロガー。</param>
    /// <param name="overlaps">重複範囲の一覧。</param>
    private static void LogActionRangeOverlaps(
        ILogger logger,
        IReadOnlyList<SecurityPolicyMergeRunResult.ActionRangeOverlap> overlaps)
    {
        if (overlaps.Count == 0)
        {
            return;
        }

        logger.LogWarning(
            "merge warning: found {ConflictCount} overlaps between different actions by original index range.",
            overlaps.Count);

        foreach (var overlap in overlaps)
        {
            logger.LogWarning(
                "overlap detail: action={LeftAction}, range=[{LeftMin}-{LeftMax}] vs action={RightAction}, range=[{RightMin}-{RightMax}]",
                overlap.Left.Action,
                overlap.Left.MinimumIndex,
                overlap.Left.MaximumIndex,
                overlap.Right.Action,
                overlap.Right.MinimumIndex,
                overlap.Right.MaximumIndex);
        }
    }
}
