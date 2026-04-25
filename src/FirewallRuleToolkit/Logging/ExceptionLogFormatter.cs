namespace FirewallRuleToolkit.Logging;

/// <summary>
/// 例外ログ向けに最小限の情報を整形します。
/// </summary>
internal static class ExceptionLogFormatter
{
    /// <summary>
    /// 例外名とメッセージ、および内包例外の例外名とメッセージを整形します。
    /// </summary>
    /// <param name="exception">整形対象の例外。</param>
    /// <returns>整形済みのサマリー文字列。</returns>
    public static string Summarize(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        var summary = $"{exception.GetType().Name}: {exception.Message}";
        if (exception.InnerException is null)
        {
            return summary;
        }

        return $"{summary} | InnerException={exception.InnerException.GetType().Name}: {exception.InnerException.Message}";
    }
}
