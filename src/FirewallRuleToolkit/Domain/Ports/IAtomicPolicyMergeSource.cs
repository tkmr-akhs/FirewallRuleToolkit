namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// merge 処理に適した順序で Atomic ポリシーを提供します。
/// </summary>
public interface IAtomicPolicyMergeSource : IReadRepository<AtomicSecurityPolicy>
{
    /// <summary>
    /// merge 処理に適した順序で Atomic ポリシーを列挙します。
    /// </summary>
    /// <returns>`FromZone`、`ToZone`、`Service.Kind`、`OriginalIndex` の順に整列され、同一 merge パーティションが連続する Atomic ポリシー列。</returns>
    IEnumerable<AtomicSecurityPolicy> GetAllOrderedForMerge();
}
