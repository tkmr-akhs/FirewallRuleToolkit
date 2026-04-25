namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// 条件付き必須パス オプションを解決します。
/// </summary>
internal static class ConditionalPathOptionResolver
{
    public static string? Resolve(
        string? path,
        bool required,
        string optionName)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            return path;
        }

        if (required)
        {
            throw new CommandUsageException($"設定ファイルまたは {optionName} で値を指定してください。");
        }

        return null;
    }
}
