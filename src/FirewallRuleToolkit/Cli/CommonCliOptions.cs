using System.CommandLine;
using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Cli;

/// <summary>
/// 全サブコマンドで共有する CLI オプションを表します。
/// </summary>
internal sealed class CommonCliOptions
{
    public required Option<string> ConfigOption { get; init; }

    public required Option<string?> DatabaseOption { get; init; }

    public required Option<LogType?> LogTypeOption { get; init; }

    public required Option<string?> LogFileOption { get; init; }

    public required Option<LogLevel?> LogLevelOption { get; init; }
}
