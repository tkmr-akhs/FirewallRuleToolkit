namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// エンティティの読み書き操作を定義します。
/// </summary>
/// <typeparam name="T">対象エンティティ型。</typeparam>
public interface IReadWriteRepository<T> : IReadRepository<T>, IWriteRepository<T>
{
}
