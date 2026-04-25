namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// 既存アドレス グループ索引を事前計算した上で、アドレス値集合を圧縮します。
/// </summary>
public sealed class AddressGroupCompactor
{
    private readonly IReadOnlyList<GroupCandidate> groupCandidates;

    /// <summary>
    /// 既存アドレス グループ索引を事前計算した上で、アドレス値集合を圧縮するクラスのコンストラクターです。
    /// </summary>
    /// <param name="rangeSplitThreshold">ハイフン範囲を分解するしきい値。</param>
    public AddressGroupCompactor(
        IReadRepository<AddressGroupMembership> addressGroups,
        ILookupRepository<string> addressObjectLookup,
        ILookupRepository<IReadOnlyList<string>> addressGroupLookup,
        int rangeSplitThreshold)
    {
        ArgumentNullException.ThrowIfNull(addressGroups);
        ArgumentNullException.ThrowIfNull(addressObjectLookup);
        ArgumentNullException.ThrowIfNull(addressGroupLookup);
        if (rangeSplitThreshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rangeSplitThreshold), rangeSplitThreshold, "Threshold must be greater than zero.");
        }

        groupCandidates = BuildGroupCandidates(addressGroups, addressObjectLookup, addressGroupLookup, rangeSplitThreshold);
    }

    /// <summary>
    /// 指定されたアドレス集合を、使える既存アドレス グループへ置き換えます。
    /// </summary>
    public CompactionResult Compact(IEnumerable<AddressValue> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        var remainingAddresses = new HashSet<AddressValue>(addresses);
        var selectedGroupNames = new List<string>();

        foreach (var candidate in groupCandidates)
        {
            if (!candidate.ResolvedAddresses.IsSubsetOf(remainingAddresses))
            {
                continue;
            }

            selectedGroupNames.Add(candidate.Name);
            remainingAddresses.ExceptWith(candidate.ResolvedAddresses);
        }

        selectedGroupNames.Sort(StringComparer.Ordinal);
        return new CompactionResult(selectedGroupNames, remainingAddresses);
    }

    /// <summary>
    /// アドレス グループ圧縮結果を表します。
    /// </summary>
    public sealed record CompactionResult(
        IReadOnlyList<string> GroupNames,
        IReadOnlyCollection<AddressValue> RemainingAddresses);

    /// <summary>
    /// リポジトリから圧縮候補となるグループ索引を構築します。
    /// </summary>
    /// <param name="addressGroups">アドレス グループ repository。</param>
    /// <param name="addressObjectLookup">アドレス オブジェクト lookup。</param>
    /// <param name="addressGroupLookup">アドレス グループ lookup。</param>
    /// <param name="rangeSplitThreshold">ハイフン範囲を分解するしきい値。</param>
    /// <returns>前計算済みのグループ候補一覧。</returns>
    private static IReadOnlyList<GroupCandidate> BuildGroupCandidates(
        IReadRepository<AddressGroupMembership> addressGroups,
        ILookupRepository<string> addressObjectLookup,
        ILookupRepository<IReadOnlyList<string>> addressGroupLookup,
        int rangeSplitThreshold)
    {
        var resolver = new AddressReferenceResolver(addressObjectLookup, addressGroupLookup);
        return addressGroups
            .GetAll()
            .GroupBy(static member => member.GroupName, StringComparer.Ordinal)
            .Select(group =>
            {
                var resolvedAddresses = AddressObjectExpander
                    .Expand(resolver.Resolve([group.Key]), rangeSplitThreshold)
                    .ToHashSet();

                return new GroupCandidate(group.Key, resolvedAddresses);
            })
            .Where(static candidate => candidate.ResolvedAddresses.Count > 1)
            .OrderByDescending(static candidate => candidate.ResolvedAddresses.Count)
            .ThenBy(static candidate => candidate.Name, StringComparer.Ordinal)
            .ToArray();
    }

    private sealed class GroupCandidate
    {
        public GroupCandidate(string name, HashSet<AddressValue> resolvedAddresses)
        {
            Name = name;
            ResolvedAddresses = resolvedAddresses;
        }

        public string Name { get; }

        public HashSet<AddressValue> ResolvedAddresses { get; }
    }
}
