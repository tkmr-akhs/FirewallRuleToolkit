namespace FirewallRuleToolkit.Domain.Exceptions;

/// <summary>
/// リポジトリからの読み取り中にデータ形式の問題が見つかったことを表す例外です。
/// </summary>
public sealed class RepositoryReadException : Exception
{
    /// <summary>
    /// リポジトリからの読み取り中にデータ形式の問題が見つかったことを表す例外のコンストラクターです。
    /// </summary>
    /// <param name="message">例外メッセージ。</param>
    /// <param name="innerException">内包例外。</param>
    public RepositoryReadException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
