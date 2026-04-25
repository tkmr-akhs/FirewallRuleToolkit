using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Cli;

/// <summary>
/// コマンド実行時に共通で参照する解決済み設定を表します。
/// </summary>
internal sealed record CommandContext(
    string? ConfigPath,
    string DatabaseDirectory,
    LogType LogType,
    string? LogFilePath,
    LogLevel LogLevel,
    ILogger Logger);
