namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// merge 処理に適した順序で Atomic ポリシーを提供します。
/// </summary>
public interface IAtomicPolicyMergeSource : IReadRepository<AtomicSecurityPolicy>
{
    /// <summary>
    /// merge 処理に適した順序で Atomic ポリシーを列挙します。
    /// </summary>
    /// <returns>merge 用に整列された Atomic ポリシー列。</returns>
    IEnumerable<AtomicSecurityPolicy> GetAllOrderedForMerge();
}
