namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merged ポリシーのシグネチャ単位統合で共通となる処理を提供します。
/// </summary>
internal abstract class SignatureBasedMergerBase
{
    /// <summary>
    /// 同じシグネチャを持つポリシー群を 1 件ずつに統合します。
    /// </summary>
    /// <param name="policies">統合対象のポリシー列。</param>
    /// <param name="signatureSelector">統合シグネチャを生成する処理。</param>
    /// <returns>シグネチャ単位で統合した結果。</returns>
    protected List<MutableMergedSecurityPolicy> MergeBySignature(
        IEnumerable<MutableMergedSecurityPolicy> policies,
        Func<MutableMergedSecurityPolicy, string> signatureSelector)
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(signatureSelector);

        return policies
            .GroupBy(signatureSelector, StringComparer.Ordinal)
            .Select(MergeSignatureSet)
            .ToList();
    }

    /// <summary>
    /// 1 つのシグネチャ集合を 1 件のポリシーへ統合します。
    /// </summary>
    /// <param name="signatureSet">同一シグネチャを持つポリシー集合。</param>
    /// <returns>統合後のポリシー。</returns>
    protected MutableMergedSecurityPolicy MergeSignatureSet(IEnumerable<MutableMergedSecurityPolicy> signatureSet)
    {
        ArgumentNullException.ThrowIfNull(signatureSet);

        using var enumerator = signatureSet.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            throw new InvalidOperationException("Merge signature set must contain at least one policy.");
        }

        var merged = MergedSecurityPolicyFactory.ClonePolicy(enumerator.Current);
        while (enumerator.MoveNext())
        {
            AbsorbMergedPolicy(merged, enumerator.Current);
        }

        return merged;
    }

    /// <summary>
    /// 具体的な統合段階ごとに異なる集合項目の統合処理を行います。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    protected abstract void MergeCollections(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source);

    /// <summary>
    /// 追跡情報を含めて 1 件のポリシーを別のポリシーへ吸収します。
    /// </summary>
    /// <param name="target">吸収先ポリシー。</param>
    /// <param name="source">吸収元ポリシー。</param>
    private void AbsorbMergedPolicy(MutableMergedSecurityPolicy target, MutableMergedSecurityPolicy source)
    {
        MergeCollections(target, source);
        target.MinimumIndex = Math.Min(target.MinimumIndex, source.MinimumIndex);
        target.MaximumIndex = Math.Max(target.MaximumIndex, source.MaximumIndex);
        target.OriginalPolicyNames.UnionWith(source.OriginalPolicyNames);
    }
}
