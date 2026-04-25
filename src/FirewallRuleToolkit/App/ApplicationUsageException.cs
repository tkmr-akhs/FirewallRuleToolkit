namespace FirewallRuleToolkit.App;

/// <summary>
/// App 層のツール利用条件が満たされていない場合に送出される例外です。
/// </summary>
internal sealed class ApplicationUsageException : Exception
{
    /// <summary>
    /// App 層のツール利用条件が満たされていない場合に送出される例外のコンストラクターです。
    /// </summary>
    /// <param name="message">例外メッセージ。</param>
    public ApplicationUsageException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// App 層のツール利用条件が満たされていない場合に送出される例外のコンストラクターです。
    /// </summary>
    /// <param name="message">例外メッセージ。</param>
    /// <param name="innerException">内包例外。</param>
    public ApplicationUsageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
