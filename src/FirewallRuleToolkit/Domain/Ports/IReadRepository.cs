namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// エンティティの読み取り操作を定義します。
/// </summary>
/// <typeparam name="T">対象エンティティ型。</typeparam>
public interface IReadRepository<out T>
{
    /// <summary>
    /// リポジトリが読み取り可能な状態かを確認します。
    /// </summary>
    void EnsureAvailable();

    /// <summary>
    /// エンティティを列挙します。
    /// </summary>
    /// <returns>エンティティの列挙。</returns>
    IEnumerable<T> GetAll();
}
