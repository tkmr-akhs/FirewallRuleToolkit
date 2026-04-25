using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// ログ関連オプションを検証して正規化します。
/// </summary>
internal static class LogCommandOptionsResolver
{
    public static ResolvedLogCommandOptions ResolveForCommand(
        LogType? logType,
        string? logFilePath,
        LogLevel? logLevel,
        string logTypeOptionName,
        string logFileOptionName,
        string logLevelOptionName)
    {
        var requiredLogType = CommandOptionValueResolver.RequireValue(logType, logTypeOptionName);
        ValidateLogType(requiredLogType);
        var requiredLogLevel = CommandOptionValueResolver.RequireValue(logLevel, logLevelOptionName);
        var resolvedLogFilePath = ResolveLogFilePath(requiredLogType, logFilePath, logFileOptionName);

        return new ResolvedLogCommandOptions(
            requiredLogType,
            resolvedLogFilePath,
            requiredLogLevel);
    }

    public static string? ResolveForLogger(
        LogType? logType,
        string? logFilePath,
        string logFileOptionName)
    {
        ValidateLogType(logType);

        return logType.HasValue
            ? ResolveLogFilePath(logType.Value, logFilePath, logFileOptionName)
            : ConditionalPathOptionResolver.Resolve(logFilePath, false, logFileOptionName);
    }

    private static string? ResolveLogFilePath(
        LogType logType,
        string? logFilePath,
        string logFileOptionName)
    {
        return logType switch
        {
            LogType.EventLog => throw new CommandUsageException("EventLog ログは未実装です。ConsoleOnly または File を指定してください。"),
            LogType.File => ConditionalPathOptionResolver.Resolve(logFilePath, true, logFileOptionName)!,
            _ => ConditionalPathOptionResolver.Resolve(logFilePath, false, logFileOptionName)
        };
    }

    private static void ValidateLogType(LogType? logType)
    {
        if (logType.HasValue && logType.Value.HasFlag(LogType.EventLog))
        {
            throw new CommandUsageException("EventLog ログは未実装です。ConsoleOnly または File を指定してください。");
        }
    }
}

internal sealed record ResolvedLogCommandOptions(
    LogType LogType,
    string? LogFilePath,
    LogLevel LogLevel);
