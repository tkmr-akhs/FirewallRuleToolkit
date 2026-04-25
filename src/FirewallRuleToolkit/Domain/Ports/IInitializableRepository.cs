namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// 書き込み先の初期化操作を定義します。
/// </summary>
public interface IInitializableRepository
{
    /// <summary>
    /// 書き込み先を初期化します。
    /// </summary>
    void Initialize();

    /// <summary>
    /// 書き込み完了時の後処理を実行します。
    /// </summary>
    void Complete();
}
