namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge 処理で同一パーティションとして扱う識別子です。
/// </summary>
internal readonly record struct MergePartitionKey(
    string FromZone,
    string ToZone,
    string? ServiceKind)
{
    /// <summary>
    /// Atomic ポリシーから merge パーティション識別子を生成します。
    /// </summary>
    /// <param name="policy">変換対象の Atomic ポリシー。</param>
    /// <returns>生成した merge パーティション識別子。</returns>
    public static MergePartitionKey FromAtomic(AtomicSecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return new MergePartitionKey(
            policy.FromZone,
            policy.ToZone,
            policy.Service.Kind);
    }
}
