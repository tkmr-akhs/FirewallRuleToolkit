namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// repository 書き込みセッションを開始します。
/// </summary>
public interface IWriteRepositorySessionFactory
{
    /// <summary>
    /// repository 書き込みセッションを開始します。
    /// </summary>
    /// <returns>開始した書き込みセッション。</returns>
    IWriteRepositorySession BeginWriteSession();
}
