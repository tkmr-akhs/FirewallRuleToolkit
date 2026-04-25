using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Logging;

/// <summary>
/// アプリケーション全体で共有するロガーを提供します。
/// </summary>
internal static class ProgramLogger
{
    private const string categoryBaseName = "fwrule-tool";

    private static ILoggerFactory? cachedLoggerFactory;
    private static ILogger? cachedLogger;
    private static LoggerConfiguration? cachedLoggerConfiguration;

    /// <summary>
    /// ログ設定に応じた共有ロガーを取得します。
    /// </summary>
    /// <param name="logType">ログ出力設定。</param>
    /// <param name="logFilePath">ログ ファイル パス。</param>
    /// <param name="logLevel">ログ レベル。</param>
    /// <returns>共有ロガー。</returns>
    public static ILogger GetLogger(LogType? logType, string? logFilePath, LogLevel? logLevel)
    {
        var requestedConfiguration = new LoggerConfiguration(
            logType,
            string.IsNullOrWhiteSpace(logFilePath) ? null : logFilePath,
            logLevel);

        if (cachedLogger is not null)
        {
            if (!ShouldReconfigure(requestedConfiguration))
            {
                return cachedLogger;
            }

            Dispose();
        }

        var loggerFactory = CreateLoggerFactory(requestedConfiguration);
        cachedLoggerFactory = loggerFactory;
        cachedLoggerConfiguration = requestedConfiguration;
        cachedLogger = loggerFactory.CreateLogger(categoryBaseName);
        return cachedLogger;
    }

    /// <summary>
    /// 共有ロガーとロガー ファクトリを破棄します。
    /// </summary>
    public static void Dispose()
    {
        cachedLogger = null;
        cachedLoggerFactory?.Dispose();
        cachedLoggerFactory = null;
        cachedLoggerConfiguration = null;
    }

    private static bool ShouldReconfigure(LoggerConfiguration requestedConfiguration)
    {
        if (!IsExplicitConfiguration(requestedConfiguration))
        {
            return false;
        }

        return !cachedLoggerConfiguration.HasValue || cachedLoggerConfiguration.Value != requestedConfiguration;
    }

    private static bool IsExplicitConfiguration(LoggerConfiguration configuration)
    {
        return configuration.LogType.HasValue
            || !string.IsNullOrWhiteSpace(configuration.LogFilePath)
            || configuration.LogLevel.HasValue;
    }

    private static ILoggerFactory CreateLoggerFactory(LoggerConfiguration configuration)
    {
        return LoggerFactory.Create(builder =>
        {
            builder.ClearProviders();
            builder.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
            });
            builder.SetMinimumLevel(configuration.LogLevel ?? LogLevel.Information);

            if (configuration.LogType.HasValue && configuration.LogType.Value.HasFlag(LogType.EventLog))
            {
                throw new NotImplementedException("EventLog logging is not implemented yet.");
            }

            if (configuration.LogType.HasValue && configuration.LogType.Value.HasFlag(LogType.File))
            {
                var requiredLogFilePath = RequireLogFilePath(configuration.LogFilePath);
                builder.AddProvider(new FileLoggerProvider(requiredLogFilePath));
            }
        });
    }

    private static string RequireLogFilePath(string? logFilePath)
    {
        if (!string.IsNullOrWhiteSpace(logFilePath))
        {
            return logFilePath;
        }

        throw new InvalidOperationException("File logging requires a log file path.");
    }

    private readonly record struct LoggerConfiguration(
        LogType? LogType,
        string? LogFilePath,
        LogLevel? LogLevel);
}
