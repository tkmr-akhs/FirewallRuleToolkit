namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// repository の件数取得操作を定義します。
/// </summary>
public interface IItemCountRepository
{
    /// <summary>
    /// repository が読み取り可能な状態かを確認します。
    /// </summary>
    void EnsureAvailable();

    /// <summary>
    /// repository に保存されている件数を取得します。
    /// </summary>
    /// <returns>保存されている件数。</returns>
    int Count();
}
