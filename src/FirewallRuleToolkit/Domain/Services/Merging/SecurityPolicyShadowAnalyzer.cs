namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// 同一 merge パーティション内の shadow 判定結果を分析します。
/// </summary>
internal static class SecurityPolicyShadowAnalyzer
{
    /// <summary>
    /// パーティション内の non-shadowed / shadowed 関係を分析します。
    /// </summary>
    /// <param name="partitionPolicies">同一 merge パーティションに属する Atomic 候補列。</param>
    /// <returns>分析結果。</returns>
    public static ShadowPartitionAnalysis Analyze(IReadOnlyList<AtomicMergeCandidate> partitionPolicies)
    {
        ArgumentNullException.ThrowIfNull(partitionPolicies);

        var nonShadowedIndices = new List<int>(partitionPolicies.Count);
        var shadowingRelations = new List<ShadowingRelation>();

        for (var candidateIndex = 0; candidateIndex < partitionPolicies.Count; candidateIndex++)
        {
            var shadowingIndex = FindShadowingIndex(partitionPolicies, nonShadowedIndices, candidateIndex);
            if (shadowingIndex < 0)
            {
                nonShadowedIndices.Add(candidateIndex);
                continue;
            }

            shadowingRelations.Add(new ShadowingRelation(candidateIndex, shadowingIndex));
        }

        return new ShadowPartitionAnalysis
        {
            NonShadowedIndices = nonShadowedIndices,
            ShadowingRelations = shadowingRelations
        };
    }

    /// <summary>
    /// 先行候補が後続候補を完全に隠しているかを判定します。
    /// </summary>
    /// <param name="frontPolicy">前方にある候補。</param>
    /// <param name="backPolicy">後方にある候補。</param>
    /// <returns>後続ルールが隠れているとき <see langword="true"/>。</returns>
    public static bool IsShadowedBy(AtomicMergeCandidate frontPolicy, AtomicMergeCandidate backPolicy)
    {
        ArgumentNullException.ThrowIfNull(frontPolicy);
        ArgumentNullException.ThrowIfNull(backPolicy);

        return frontPolicy.MinimumIndex < backPolicy.MinimumIndex
            && SecurityPolicyContainment.IsApplicationContaining(frontPolicy.Application, backPolicy.Application)
            && SecurityPolicyContainment.IsAddressContaining(frontPolicy.SourceAddress, backPolicy.SourceAddress)
            && SecurityPolicyContainment.IsAddressContaining(frontPolicy.DestinationAddress, backPolicy.DestinationAddress)
            && SecurityPolicyContainment.IsServiceContaining(frontPolicy.Service, backPolicy.Service);
    }

    /// <summary>
    /// shadow 分析の結果です。
    /// </summary>
    internal sealed class ShadowPartitionAnalysis
    {
        /// <summary>
        /// non-shadowed な候補の元インデックス一覧を取得します。
        /// </summary>
        public IReadOnlyList<int> NonShadowedIndices { get; init; } = [];

        /// <summary>
        /// shadowed 候補と shadow を作った先行候補の対応関係一覧を取得します。
        /// </summary>
        public IReadOnlyList<ShadowingRelation> ShadowingRelations { get; init; } = [];
    }

    /// <summary>
    /// shadowed 候補と、それを隠した先行候補の対応です。
    /// </summary>
    /// <param name="ShadowedIndex">shadowed になった候補の元位置。</param>
    /// <param name="ShadowingIndex">shadow を作った non-shadowed 候補の元位置。</param>
    internal readonly record struct ShadowingRelation(
        int ShadowedIndex,
        int ShadowingIndex);

    /// <summary>
    /// 候補を隠す non-shadowed 候補の元位置を返します。
    /// </summary>
    /// <param name="partitionPolicies">対象パーティション。</param>
    /// <param name="nonShadowedIndices">現時点で non-shadowed 判定済みの候補位置一覧。</param>
    /// <param name="candidateIndex">判定対象候補位置。</param>
    /// <returns>隠す候補がある場合はその位置。なければ -1。</returns>
    private static int FindShadowingIndex(
        IReadOnlyList<AtomicMergeCandidate> partitionPolicies,
        IReadOnlyList<int> nonShadowedIndices,
        int candidateIndex)
    {
        foreach (var nonShadowedIndex in nonShadowedIndices)
        {
            if (IsShadowedBy(partitionPolicies[nonShadowedIndex], partitionPolicies[candidateIndex]))
            {
                return nonShadowedIndex;
            }
        }

        return -1;
    }
}
