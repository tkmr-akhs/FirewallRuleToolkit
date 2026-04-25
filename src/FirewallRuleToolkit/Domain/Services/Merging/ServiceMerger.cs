namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// サービス集合だけが異なるポリシーを統合します。
/// </summary>
internal sealed class ServiceMerger : SignatureBasedMergerBase
{
    /// <summary>
    /// サービス統合段階を実行します。
    /// </summary>
    /// <param name="policies">統合対象のポリシー列。</param>
    /// <returns>サービス シグネチャ単位で統合した結果。</returns>
    public List<MutableMergedSecurityPolicy> Merge(IEnumerable<MutableMergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        return MergeBySignature(policies, CreateMergeSignature);
    }

    /// <summary>
    /// サービス集合を吸収先ポリシーへ統合します。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    protected override void MergeCollections(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source)
    {
        target.Services.UnionWith(source.Services);
    }

    /// <summary>
    /// サービス統合に使う比較シグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>サービス統合用の比較シグネチャ。</returns>
    private static string CreateMergeSignature(MutableMergedSecurityPolicy policy)
    {
        return string.Concat(
            "fz=", MergeSignatureFormatter.BuildStringSetSignature(policy.FromZones),
            "|sa=", MergeSignatureFormatter.BuildAddressSetSignature(policy.SourceAddresses),
            "|tz=", MergeSignatureFormatter.BuildStringSetSignature(policy.ToZones),
            "|da=", MergeSignatureFormatter.BuildAddressSetSignature(policy.DestinationAddresses),
            "|ap=", MergeSignatureFormatter.BuildStringSetSignature(policy.Applications),
            "|ac=", policy.Action,
            "|gid=", MergeSignatureFormatter.BuildStringSignature(policy.GroupId));
    }
}
