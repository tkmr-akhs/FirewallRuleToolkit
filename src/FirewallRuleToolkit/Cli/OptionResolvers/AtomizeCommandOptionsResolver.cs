namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// atomize サブコマンドのオプションを検証して正規化します。
/// </summary>
internal static class AtomizeCommandOptionsResolver
{
    /// <summary>
    /// atomize サブコマンドのしきい値を検証します。
    /// </summary>
    /// <param name="threshold">しきい値。</param>
    /// <param name="thresholdOptionName">しきい値オプション名。</param>
    /// <returns>検証済みのしきい値。</returns>
    public static int ResolveThreshold(int? threshold, string thresholdOptionName)
    {
        var requiredThreshold = CommandOptionValueResolver.RequireValue(threshold, thresholdOptionName);
        if (requiredThreshold <= 0)
        {
            throw new CommandUsageException("threshold は 1 以上で指定してください。");
        }

        return requiredThreshold;
    }
}
