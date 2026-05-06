namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// 送信元アドレス集合だけが異なるポリシーを統合します。
/// </summary>
internal sealed class SourceAddressMerger : SignatureBasedMergerBase
{
    /// <summary>
    /// 送信元アドレス統合段階を実行します。
    /// </summary>
    /// <param name="policies">統合対象のポリシー列。</param>
    /// <returns>送信元アドレス シグネチャ単位で統合した結果。</returns>
    public List<MutableMergedSecurityPolicy> Merge(IEnumerable<MutableMergedSecurityPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        return MergeBySignature(policies, CreateMergeSignature);
    }

    /// <summary>
    /// 送信元アドレス集合を吸収先ポリシーへ統合します。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    protected override void MergeCollections(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source)
    {
        AddressConditionSetOperations.AbsorbConfiguredIdentity(target.SourceAddresses, source.SourceAddresses);
    }

    /// <summary>
    /// 送信元アドレス統合に使う比較シグネチャを生成します。
    /// </summary>
    /// <param name="policy">シグネチャ生成対象の候補。</param>
    /// <returns>送信元アドレス統合用の比較シグネチャ。</returns>
    private static string CreateMergeSignature(MutableMergedSecurityPolicy policy)
    {
        return string.Concat(
            "fz=", MergeSignatureBuilder.OrdinalStringSet(policy.FromZones),
            "|tz=", MergeSignatureBuilder.OrdinalStringSet(policy.ToZones),
            "|da=", MergeSignatureBuilder.AddressConfiguredIdentitySet(policy.DestinationAddresses),
            "|ap=", MergeSignatureBuilder.ApplicationConfiguredIdentitySet(policy.Applications),
            "|sv=", MergeSignatureBuilder.ServiceConfiguredIdentitySet(policy.Services),
            "|ac=", policy.Action,
            "|gid=", MergeSignatureBuilder.OrdinalStringValue(policy.GroupId));
    }
}
