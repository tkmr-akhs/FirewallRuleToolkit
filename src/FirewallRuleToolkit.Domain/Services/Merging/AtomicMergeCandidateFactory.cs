namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// Atomic ポリシーを merge 用の中間表現へ変換します。
/// </summary>
internal static class AtomicMergeCandidateFactory
{
    /// <summary>
    /// Atomic ポリシー 1 件をマージ候補へ変換します。
    /// </summary>
    /// <param name="policy">変換対象の Atomic ポリシー。</param>
    /// <returns>変換したマージ候補。</returns>
    public static AtomicMergeCandidate CreateFromAtomic(AtomicSecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

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
            MinimumIndex = policy.OriginalIndex,
            MaximumIndex = policy.OriginalIndex,
            OriginalPolicyNames = new HashSet<string>(StringComparer.Ordinal) { policy.OriginalPolicyName }
        };
    }
}
