namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// 名前による Lookup 操作を定義します。
/// </summary>
/// <typeparam name="TValue">取得対象の値型。</typeparam>
public interface ILookupRepository<TValue>
{
    /// <summary>
    /// リポジトリが読み取り可能な状態かを確認します。
    /// </summary>
    void EnsureAvailable();

    /// <summary>
    /// 指定した名前に対応する値を取得します。
    /// </summary>
    /// <param name="name">名前。</param>
    /// <param name="value">見つかった場合に設定される値。</param>
    /// <returns>値が見つかった場合は <see langword="true"/>。</returns>
    bool TryGetByName(string name, out TValue value);
}
