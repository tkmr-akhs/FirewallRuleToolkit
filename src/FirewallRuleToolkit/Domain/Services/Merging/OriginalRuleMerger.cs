namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// 同じ元ルール由来の非 Allow ポリシーを統合します。
/// </summary>
internal sealed class OriginalRuleMerger : SignatureBasedMergerBase
{
    /// <summary>
    /// 元ルール単位の統合段階を実行します。
    /// </summary>
    /// <param name="policies">統合対象のポリシー列。</param>
    /// <returns>元ルール シグネチャ単位で統合した結果。</returns>
    public List<MutableMergedSecurityPolicy> Merge(IEnumerable<MutableMergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        return MergeBySignature(policies, CreateMergeSignature);
    }

    /// <summary>
    /// 全ての可変集合を吸収先ポリシーへ統合します。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    protected override void MergeCollections(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source)
    {
        target.FromZones.UnionWith(source.FromZones);
        target.SourceAddresses.UnionWith(source.SourceAddresses);
        target.ToZones.UnionWith(source.ToZones);
        target.DestinationAddresses.UnionWith(source.DestinationAddresses);
        target.Applications.UnionWith(source.Applications);
        target.Services.UnionWith(source.Services);
    }

    /// <summary>
    /// 元ルール単位統合に使う比較シグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>元ルール統合用の比較シグネチャ。</returns>
    private static string CreateMergeSignature(MutableMergedSecurityPolicy policy)
    {
        return string.Concat(
            "ac=", policy.Action,
            "|gid=", MergeSignatureFormatter.BuildStringSignature(policy.GroupId),
            "|min=", policy.MinimumIndex,
            "|max=", policy.MaximumIndex,
            "|orig=", MergeSignatureFormatter.BuildStringSetSignature(policy.OriginalPolicyNames));
    }
}
