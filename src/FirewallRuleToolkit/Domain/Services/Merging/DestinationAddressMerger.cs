namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// 宛先アドレス集約と well-known port 例外を扱います。
/// </summary>
internal sealed class DestinationAddressMerger : SignatureBasedMergerBase
{
    /// <summary>
    /// small well-known destination ports 条件判定を行います。
    /// </summary>
    private readonly SmallWellKnownDestinationPortMatcher smallWellKnownDestinationPortMatcher;

    /// <summary>
    /// デバッグ ログ出力先です。
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// 宛先アドレスを集約するクラスのコンストラクターです。
    /// </summary>
    /// <param name="smallWellKnownDestinationPortMatcher">well-known 条件判定。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public DestinationAddressMerger(
        SmallWellKnownDestinationPortMatcher smallWellKnownDestinationPortMatcher,
        ILogger? logger = null)
    {
        this.smallWellKnownDestinationPortMatcher = smallWellKnownDestinationPortMatcher
            ?? throw new ArgumentNullException(nameof(smallWellKnownDestinationPortMatcher));
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// 宛先アドレス差異を吸収する段階を実行します。
    /// </summary>
    /// <param name="policies">統合対象の merged 候補列。</param>
    /// <returns>宛先アドレス差異を吸収した結果。</returns>
    public List<MutableMergedSecurityPolicy> Merge(IEnumerable<MutableMergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        return policies
            .GroupBy(CreateMergeSignature, StringComparer.Ordinal)
            .SelectMany(SplitDestinationAddressSignatureSetIfNeeded)
            .Select(MergeSignatureSet)
            .ToList();
    }

    /// <summary>
    /// 宛先アドレス集合を吸収先ポリシーへ統合します。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    protected override void MergeCollections(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source)
    {
        target.DestinationAddresses.UnionWith(source.DestinationAddresses);
    }

    /// <summary>
    /// well-known port 条件に応じて、宛先アドレス集約候補を再分割します。
    /// </summary>
    /// <param name="signatureSet">同一宛先集約シグネチャを持つ候補集合。</param>
    /// <returns>分割後の候補集合列。</returns>
    private IEnumerable<IEnumerable<MutableMergedSecurityPolicy>> SplitDestinationAddressSignatureSetIfNeeded(
        IGrouping<string, MutableMergedSecurityPolicy> signatureSet)
    {
        var materialized = signatureSet.ToArray();
        if (!ShouldKeepDestinationAddressesSeparated(materialized))
        {
            return [materialized];
        }

        if (smallWellKnownDestinationPortMatcher.TryGetSmallWellKnownDestinationPorts(
            materialized.SelectMany(static policy => policy.Services),
            out var destinationPorts))
        {
            LogDestinationAddressAggregationSkipped(materialized, destinationPorts);
        }

        return materialized
            .GroupBy(
                BuildDestinationAddressSetSignature,
                StringComparer.Ordinal)
            .Select(static addressSignatureSet => addressSignatureSet.AsEnumerable())
            .ToArray();
    }

    /// <summary>
    /// 宛先アドレス統合に使う比較シグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>宛先アドレス統合用の比較シグネチャ。</returns>
    private static string CreateMergeSignature(MutableMergedSecurityPolicy policy)
    {
        return string.Concat(
            "fz=", MergeSignatureFormatter.BuildStringSetSignature(policy.FromZones),
            "|sa=", MergeSignatureFormatter.BuildAddressSetSignature(policy.SourceAddresses),
            "|tz=", MergeSignatureFormatter.BuildStringSetSignature(policy.ToZones),
            "|ap=", MergeSignatureFormatter.BuildStringSetSignature(policy.Applications),
            "|sv=", MergeSignatureFormatter.BuildServiceSetSignature(policy.Services),
            "|ac=", policy.Action,
            "|gid=", MergeSignatureFormatter.BuildStringSignature(policy.GroupId));
    }

    /// <summary>
    /// 宛先アドレス集合そのものを識別するシグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>宛先アドレス集合識別用シグネチャ。</returns>
    private static string BuildDestinationAddressSetSignature(MutableMergedSecurityPolicy policy)
    {
        return MergeSignatureFormatter.BuildAddressSetSignature(policy.DestinationAddresses);
    }

    /// <summary>
    /// 宛先アドレスの分離維持が必要かどうかを判定します。
    /// </summary>
    /// <param name="policies">判定対象の候補群。</param>
    /// <returns>分離維持が必要なとき <see langword="true"/>。</returns>
    private bool ShouldKeepDestinationAddressesSeparated(
        IReadOnlyCollection<MutableMergedSecurityPolicy> policies)
    {
        return smallWellKnownDestinationPortMatcher.TryGetSmallWellKnownDestinationPorts(
            policies.SelectMany(static policy => policy.Services),
            out _);
    }

    /// <summary>
    /// 宛先アドレス集約を抑止したことをデバッグ ログへ出力します。
    /// </summary>
    /// <param name="policies">分離維持対象の候補群。</param>
    /// <param name="destinationPorts">該当した宛先ポート一覧。</param>
    private void LogDestinationAddressAggregationSkipped(
        IReadOnlyCollection<MutableMergedSecurityPolicy> policies,
        IReadOnlyList<uint> destinationPorts)
    {
        logger.LogDebugIfEnabled(log =>
            log.LogDebug(
                "merge debug: kept destination addresses separated because services are small well-known destination ports. policyCount={PolicyCount}, destinationPorts={DestinationPorts}",
                policies.Count,
                FormatUIntValues(destinationPorts)));
    }

    /// <summary>
    /// 数値列をログ向けのカンマ区切り文字列へ変換します。
    /// </summary>
    /// <param name="values">対象値列。</param>
    /// <returns>ログ向け文字列。</returns>
    private static string FormatUIntValues(IEnumerable<uint> values)
    {
        return string.Join(",", values.OrderBy(static value => value));
    }
}
