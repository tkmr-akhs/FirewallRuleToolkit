namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge 処理中だけ利用する可変の merged ポリシーです。
/// </summary>
internal sealed class MutableMergedSecurityPolicy
{
    /// <summary>
    /// 可変 merged ポリシーを初期化します。
    /// </summary>
    /// <param name="fromZones">送信元ゾーン一覧。</param>
    /// <param name="sourceAddresses">送信元アドレス一覧。</param>
    /// <param name="toZones">宛先ゾーン一覧。</param>
    /// <param name="destinationAddresses">宛先アドレス一覧。</param>
    /// <param name="applications">アプリケーション一覧。</param>
    /// <param name="services">サービス定義一覧。</param>
    /// <param name="action">アクション。</param>
    /// <param name="groupId">グループ識別子。空文字列も有効な識別子として扱います。</param>
    /// <param name="minimumIndex">最小インデックス。</param>
    /// <param name="maximumIndex">最大インデックス。</param>
    /// <param name="originalPolicyNames">元ポリシー名集合。</param>
    public MutableMergedSecurityPolicy(
        IEnumerable<string> fromZones,
        IEnumerable<AddressValue> sourceAddresses,
        IEnumerable<string> toZones,
        IEnumerable<AddressValue> destinationAddresses,
        IEnumerable<string> applications,
        IEnumerable<ServiceValue> services,
        SecurityPolicyAction action,
        string groupId,
        ulong minimumIndex,
        ulong maximumIndex,
        IEnumerable<string> originalPolicyNames)
    {
        ArgumentNullException.ThrowIfNull(fromZones);
        ArgumentNullException.ThrowIfNull(sourceAddresses);
        ArgumentNullException.ThrowIfNull(toZones);
        ArgumentNullException.ThrowIfNull(destinationAddresses);
        ArgumentNullException.ThrowIfNull(applications);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(groupId);
        ArgumentNullException.ThrowIfNull(originalPolicyNames);

        FromZones = new HashSet<string>(fromZones, StringComparer.Ordinal);
        SourceAddresses = new HashSet<AddressValue>(sourceAddresses);
        ToZones = new HashSet<string>(toZones, StringComparer.Ordinal);
        DestinationAddresses = new HashSet<AddressValue>(destinationAddresses);
        Applications = new HashSet<string>(applications, StringComparer.Ordinal);
        Services = new HashSet<ServiceValue>(services);
        Action = action;
        GroupId = groupId;
        MinimumIndex = minimumIndex;
        MaximumIndex = maximumIndex;
        OriginalPolicyNames = new HashSet<string>(originalPolicyNames, StringComparer.Ordinal);
    }

    /// <summary>
    /// 送信元ゾーン一覧を取得します。
    /// </summary>
    public HashSet<string> FromZones { get; }

    /// <summary>
    /// 送信元アドレス一覧を取得します。
    /// </summary>
    public HashSet<AddressValue> SourceAddresses { get; }

    /// <summary>
    /// 宛先ゾーン一覧を取得します。
    /// </summary>
    public HashSet<string> ToZones { get; }

    /// <summary>
    /// 宛先アドレス一覧を取得します。
    /// </summary>
    public HashSet<AddressValue> DestinationAddresses { get; }

    /// <summary>
    /// アプリケーション一覧を取得します。
    /// </summary>
    public HashSet<string> Applications { get; }

    /// <summary>
    /// サービス定義一覧を取得します。
    /// </summary>
    public HashSet<ServiceValue> Services { get; }

    /// <summary>
    /// アクションを取得します。
    /// </summary>
    public SecurityPolicyAction Action { get; }

    /// <summary>
    /// グループ識別子を取得します。空文字列も有効な識別子として扱います。
    /// </summary>
    public string GroupId { get; }

    /// <summary>
    /// 最小インデックスを取得または設定します。
    /// </summary>
    public ulong MinimumIndex { get; set; }

    /// <summary>
    /// 最大インデックスを取得または設定します。
    /// </summary>
    public ulong MaximumIndex { get; set; }

    /// <summary>
    /// 元ポリシー名集合を取得します。
    /// </summary>
    public HashSet<string> OriginalPolicyNames { get; }

    /// <summary>
    /// 読み取り専用の merged ポリシーから可変候補を生成します。
    /// </summary>
    /// <param name="policy">変換元の merged ポリシー。</param>
    /// <returns>可変候補。</returns>
    public static MutableMergedSecurityPolicy FromMergedSecurityPolicy(MergedSecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return new MutableMergedSecurityPolicy(
            policy.FromZones,
            policy.SourceAddresses,
            policy.ToZones,
            policy.DestinationAddresses,
            policy.Applications,
            policy.Services,
            policy.Action,
            policy.GroupId,
            policy.MinimumIndex,
            policy.MaximumIndex,
            policy.OriginalPolicyNames);
    }

    /// <summary>
    /// 読み取り専用の merged ポリシーへ変換します。
    /// </summary>
    /// <returns>読み取り専用の merged ポリシー。</returns>
    public MergedSecurityPolicy ToMergedSecurityPolicy()
    {
        return new MergedSecurityPolicy
        {
            FromZones = FromZones,
            SourceAddresses = SourceAddresses,
            ToZones = ToZones,
            DestinationAddresses = DestinationAddresses,
            Applications = Applications,
            Services = Services,
            Action = Action,
            GroupId = GroupId,
            MinimumIndex = MinimumIndex,
            MaximumIndex = MaximumIndex,
            OriginalPolicyNames = OriginalPolicyNames
        };
    }
}
