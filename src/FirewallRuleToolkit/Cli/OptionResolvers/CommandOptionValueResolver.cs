namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// 必須オプション値の解決を支援します。
/// </summary>
internal static class CommandOptionValueResolver
{
    public static string RequireValue(string? value, string optionName)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        throw new CommandUsageException($"設定ファイルまたは {optionName} で値を指定してください。");
    }

    public static T RequireValue<T>(T? value, string optionName)
        where T : struct
    {
        if (value.HasValue)
        {
            return value.Value;
        }

        throw new CommandUsageException($"設定ファイルまたは {optionName} で値を指定してください。");
    }
}
