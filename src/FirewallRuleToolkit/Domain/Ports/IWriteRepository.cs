namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// エンティティの書き込み操作を定義します。
/// </summary>
/// <typeparam name="T">対象エンティティ型。</typeparam>
public interface IWriteRepository<in T> : IInitializableRepository
{
    /// <summary>
    /// エンティティを追記します。
    /// </summary>
    /// <param name="items">追記するエンティティの列挙。</param>
    void AppendRange(IEnumerable<T> items);

    /// <summary>
    /// エンティティを置き換えます。
    /// </summary>
    /// <param name="items">書き込むエンティティの列挙。</param>
    void ReplaceAll(IEnumerable<T> items);
}
