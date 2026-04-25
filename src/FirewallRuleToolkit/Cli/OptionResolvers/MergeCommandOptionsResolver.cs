namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// merge サブコマンドのオプションを検証して正規化します。
/// </summary>
internal static class MergeCommandOptionsResolver
{
    public static ResolvedMergeCommandOptions Resolve(
        string? wkPort,
        uint? wkpThreshold,
        uint? hsPercent,
        string hsPercentOptionName)
    {
        var requiredHsPercent = CommandOptionValueResolver.RequireValue(hsPercent, hsPercentOptionName);
        ValidateHsPercent(requiredHsPercent);

        var hasWkPort = !string.IsNullOrWhiteSpace(wkPort);
        var hasWkpThreshold = wkpThreshold.HasValue;
        if (!hasWkPort && !hasWkpThreshold)
        {
            return new ResolvedMergeCommandOptions(new HashSet<uint>(), null, requiredHsPercent, null);
        }

        if (!hasWkPort || !hasWkpThreshold)
        {
            throw new CommandUsageException("merge の wkport 制御を有効にする場合は、--wkport と --wkpthreshold を両方指定してください。");
        }

        var ports = new HashSet<uint>();
        foreach (var token in wkPort!.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.Contains('-', StringComparison.Ordinal))
            {
                throw new CommandUsageException("wkport では範囲指定を使えません。\"80,443\" のように個別ポートを指定してください。");
            }

            if (!uint.TryParse(token, out var port) || port > 65535)
            {
                throw new CommandUsageException($"wkport に無効なポートが含まれています: \"{token}\"");
            }

            ports.Add(port);
        }

        if (ports.Count == 0)
        {
            throw new CommandUsageException("wkport には 1 つ以上のポートを指定してください。");
        }

        return new ResolvedMergeCommandOptions(
            ports,
            wkpThreshold,
            requiredHsPercent,
            string.Join(",", ports.OrderBy(static port => port)));
    }

    private static void ValidateHsPercent(uint hsPercent)
    {
        if (hsPercent is < 1 or > 100)
        {
            throw new CommandUsageException("hspercent は 1 から 100 の範囲で指定してください。");
        }
    }
}

internal sealed record ResolvedMergeCommandOptions(
    IReadOnlySet<uint> WellKnownDestinationPorts,
    uint? WkpThreshold,
    uint HsPercent,
    string? WkPortLogValue);
