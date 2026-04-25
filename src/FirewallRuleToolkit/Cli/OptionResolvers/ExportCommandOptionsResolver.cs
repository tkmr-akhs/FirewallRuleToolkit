using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Cli.OptionResolvers;

/// <summary>
/// export サブコマンドのオプションを検証して正規化します。
/// </summary>
internal static class ExportCommandOptionsResolver
{
    public static ResolvedExportCommandOptions Resolve(
        ExportTarget? target,
        string? atomicPath,
        string? mergedPath,
        string targetOptionName,
        string atomicOptionName,
        string mergedOptionName)
    {
        var requiredTarget = CommandOptionValueResolver.RequireValue(target, targetOptionName);
        if (requiredTarget == ExportTarget.None)
        {
            throw new CommandUsageException("Select at least one export target.");
        }

        return new ResolvedExportCommandOptions(
            requiredTarget,
            ResolveSelectedPath(
                atomicPath,
                selected: requiredTarget.HasFlag(ExportTarget.Atomic),
                atomicOptionName),
            ResolveSelectedPath(
                mergedPath,
                selected: requiredTarget.HasFlag(ExportTarget.Merged),
                mergedOptionName));
    }

    private static string? ResolveSelectedPath(string? path, bool selected, string optionName)
    {
        return selected
            ? ConditionalPathOptionResolver.Resolve(path, required: true, optionName)
            : null;
    }
}

internal sealed record ResolvedExportCommandOptions(
    ExportTarget Target,
    string? AtomicPath,
    string? MergedPath);
