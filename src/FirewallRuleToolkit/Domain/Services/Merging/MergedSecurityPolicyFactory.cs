namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge 処理用ポリシーの生成を補助します。
/// </summary>
internal static class MergedSecurityPolicyFactory
{
    /// <summary>
    /// Atomic 1 件を要素数 1 の mutable merged 候補へ変換します。
    /// </summary>
    /// <param name="policy">変換対象の Atomic。</param>
    /// <returns>変換結果。</returns>
    public static MutableMergedSecurityPolicy CreateFromAtomic(AtomicMergeCandidate policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return new MutableMergedSecurityPolicy(
            [policy.FromZone],
            [policy.SourceAddress],
            [policy.ToZone],
            [policy.DestinationAddress],
            [policy.Application],
            [policy.Service],
            policy.Action,
            policy.GroupId,
            policy.MinimumIndex,
            policy.MaximumIndex,
            policy.OriginalPolicyNames);
    }

    /// <summary>
    /// マージ処理用に候補を複製します。
    /// </summary>
    /// <param name="source">複製元の mutable merged 候補。</param>
    /// <returns>複製した mutable merged 候補。</returns>
    public static MutableMergedSecurityPolicy ClonePolicy(MutableMergedSecurityPolicy source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return CreateFromTemplate(
            source,
            source.SourceAddresses,
            source.DestinationAddresses,
            source.Services,
            source.MinimumIndex,
            source.MaximumIndex,
            source.OriginalPolicyNames);
    }

    /// <summary>
    /// テンプレート候補から任意の集合と追跡情報を持つ新規ルールを組み立てます。
    /// </summary>
    /// <param name="template">固定項目を引き継ぐ元候補。</param>
    /// <param name="sourceAddresses">送信元集合。</param>
    /// <param name="destinationAddresses">宛先集合。</param>
    /// <param name="services">サービス集合。</param>
    /// <param name="minimumIndex">最小インデックス。</param>
    /// <param name="maximumIndex">最大インデックス。</param>
    /// <param name="originalPolicyNames">元ポリシー名集合。</param>
    /// <returns>生成したルール。</returns>
    public static MutableMergedSecurityPolicy CreateFromTemplate(
        MutableMergedSecurityPolicy template,
        IEnumerable<AddressValue> sourceAddresses,
        IEnumerable<AddressValue> destinationAddresses,
        IEnumerable<ServiceValue> services,
        ulong minimumIndex,
        ulong maximumIndex,
        IEnumerable<string> originalPolicyNames)
    {
        ArgumentNullException.ThrowIfNull(template);

        return new MutableMergedSecurityPolicy(
            template.FromZones,
            sourceAddresses,
            template.ToZones,
            destinationAddresses,
            template.Applications,
            services,
            template.Action,
            template.GroupId,
            minimumIndex,
            maximumIndex,
            originalPolicyNames);
    }
}
