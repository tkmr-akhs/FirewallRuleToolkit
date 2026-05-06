namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// Domain サービス内のログ出力補助を提供します。
/// </summary>
internal static class DomainLoggerExtensions
{
    /// <summary>
    /// ロガー未指定時に破棄ロガーへ正規化します。
    /// </summary>
    /// <param name="logger">正規化対象のロガー。</param>
    /// <returns>利用可能なロガー。</returns>
    internal static ILogger OrNullLogger(this ILogger? logger)
    {
        return logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    /// <summary>
    /// Debug レベルが有効な場合だけログ書き込み処理を実行します。
    /// </summary>
    /// <param name="logger">出力先ロガー。</param>
    /// <param name="writeLog">ログ書き込み処理。</param>
    internal static void LogDebugIfEnabled(this ILogger logger, Action<ILogger> writeLog)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(writeLog);

        if (logger.IsEnabled(LogLevel.Debug))
        {
            writeLog(logger);
        }
    }
}
