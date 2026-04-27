namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// Allow の Atomic マージ候補から完全包含された候補を取り除きます。
/// </summary>
internal static class AtomicMergeCandidateDeduplicator
{
    /// <summary>
    /// 完全に包含される Atomic マージ候補を先に取り除きます。
    /// </summary>
    /// <param name="policies">判定対象のマージ候補列。</param>
    /// <returns>包含除去後の候補一覧。</returns>
    public static List<AtomicMergeCandidate> RemoveContainedPolicies(IReadOnlyList<AtomicMergeCandidate> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);

        var items = policies
            .Select(ClonePolicy)
            .ToList();

        var removed = new bool[items.Count];
        for (var leftIndex = 0; leftIndex < items.Count; leftIndex++)
        {
            if (removed[leftIndex])
            {
                continue;
            }

            for (var rightIndex = leftIndex + 1; rightIndex < items.Count; rightIndex++)
            {
                if (removed[rightIndex])
                {
                    continue;
                }

                var left = items[leftIndex];
                var right = items[rightIndex];
                if (Contains(left, right))
                {
                    Absorb(left, right);
                    removed[rightIndex] = true;
                    continue;
                }

                if (Contains(right, left))
                {
                    Absorb(right, left);
                    removed[leftIndex] = true;
                    break;
                }
            }
        }

        var survivors = new List<AtomicMergeCandidate>();
        for (var index = 0; index < items.Count; index++)
        {
            if (!removed[index])
            {
                survivors.Add(items[index]);
            }
        }

        return survivors;
    }

    /// <summary>
    /// 判定用に Atomic 候補を複製します。
    /// </summary>
    /// <param name="policy">複製元候補。</param>
    /// <returns>複製した候補。</returns>
    private static AtomicMergeCandidate ClonePolicy(AtomicMergeCandidate policy)
    {
        return new AtomicMergeCandidate
        {
            FromZone = policy.FromZone,
            SourceAddress = policy.SourceAddress,
            ToZone = policy.ToZone,
            DestinationAddress = policy.DestinationAddress,
            Application = policy.Application,
            Service = policy.Service,
            Action = policy.Action,
            GroupId = policy.GroupId,
            MinimumIndex = policy.MinimumIndex,
            MaximumIndex = policy.MaximumIndex,
            OriginalPolicyNames = new HashSet<string>(policy.OriginalPolicyNames, StringComparer.Ordinal)
        };
    }

    /// <summary>
    /// 吸収される候補のトレーサビリティ情報を生存側へ寄せます。
    /// </summary>
    /// <param name="survivor">生存する候補。</param>
    /// <param name="removed">吸収される候補。</param>
    private static void Absorb(AtomicMergeCandidate survivor, AtomicMergeCandidate removed)
    {
        survivor.MinimumIndex = Math.Min(survivor.MinimumIndex, removed.MinimumIndex);
        survivor.MaximumIndex = Math.Max(survivor.MaximumIndex, removed.MaximumIndex);
        survivor.OriginalPolicyNames.UnionWith(removed.OriginalPolicyNames);
    }

    /// <summary>
    /// 片方の Atomic 候補がもう片方を包含するかを判定します。
    /// </summary>
    /// <param name="container">包含側候補。</param>
    /// <param name="contained">被包含側候補。</param>
    /// <returns>包含するとき <see langword="true"/>。</returns>
    private static bool Contains(AtomicMergeCandidate container, AtomicMergeCandidate contained)
    {
        return string.Equals(container.FromZone, contained.FromZone, StringComparison.Ordinal)
            && string.Equals(container.ToZone, contained.ToZone, StringComparison.Ordinal)
            && container.Action == contained.Action
            && string.Equals(container.GroupId, contained.GroupId, StringComparison.Ordinal)
            && EffectivePolicyConditionContainment.AddressCovers(container.SourceAddress, contained.SourceAddress)
            && EffectivePolicyConditionContainment.AddressCovers(container.DestinationAddress, contained.DestinationAddress)
            && EffectivePolicyConditionContainment.ApplicationCovers(container.Application, contained.Application)
            && EffectivePolicyConditionContainment.ServiceCovers(container.Service, contained.Service);
    }
}
