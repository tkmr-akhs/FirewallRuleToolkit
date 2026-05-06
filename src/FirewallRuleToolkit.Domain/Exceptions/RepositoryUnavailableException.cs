namespace FirewallRuleToolkit.Domain.Exceptions;

/// <summary>
/// リポジトリの利用可否に問題があることを表す例外です。
/// </summary>
public sealed class RepositoryUnavailableException : Exception
{
    /// <summary>
    /// リポジトリの利用可否に問題があることを表す例外のコンストラクターです。
    /// </summary>
    /// <param name="message">例外メッセージ。</param>
    /// <param name="innerException">内包例外。</param>
    public RepositoryUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
