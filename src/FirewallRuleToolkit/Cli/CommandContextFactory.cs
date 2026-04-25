using System.CommandLine;
using System.CommandLine.Parsing;
using FirewallRuleToolkit.Cli.OptionResolvers;

namespace FirewallRuleToolkit.Cli;

/// <summary>
/// ParseResult からコマンド実行用コンテキストを生成します。
/// </summary>
internal static class CommandContextFactory
{
    public static CommandContext Create(ParseResult parseResult, CommonCliOptions commonOptions)
    {
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);

        var databaseDirectory = CommandOptionValueResolver.RequireValue(
            parseResult.GetValue(commonOptions.DatabaseOption),
            commonOptions.DatabaseOption.Name);
        var logOptions = LogCommandOptionsResolver.ResolveForCommand(
            parseResult.GetValue(commonOptions.LogTypeOption),
            parseResult.GetValue(commonOptions.LogFileOption),
            parseResult.GetValue(commonOptions.LogLevelOption),
            commonOptions.LogTypeOption.Name,
            commonOptions.LogFileOption.Name,
            commonOptions.LogLevelOption.Name);

        return new CommandContext(
            parseResult.GetValue(commonOptions.ConfigOption),
            databaseDirectory,
            logOptions.LogType,
            logOptions.LogFilePath,
            logOptions.LogLevel,
            ProgramLogger.GetLogger(logOptions.LogType, logOptions.LogFilePath, logOptions.LogLevel));
    }

    public static ILogger CreateLogger(ParseResult parseResult, CommonCliOptions commonOptions)
    {
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);

        var logType = parseResult.GetValue(commonOptions.LogTypeOption);
        var logFilePath = LogCommandOptionsResolver.ResolveForLogger(
            logType,
            parseResult.GetValue(commonOptions.LogFileOption),
            commonOptions.LogFileOption.Name);

        return ProgramLogger.GetLogger(
            logType,
            logFilePath,
            parseResult.GetValue(commonOptions.LogLevelOption));
    }
}
