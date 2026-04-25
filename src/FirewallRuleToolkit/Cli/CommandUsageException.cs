namespace FirewallRuleToolkit.Cli;

/// <summary>
/// CLI 入力が不正な場合に送出される例外です。
/// </summary>
internal sealed class CommandUsageException(string message) : Exception(message)
{
}
