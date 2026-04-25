using FirewallRuleToolkit.Cli.OptionResolvers;
using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Tests.Cli.OptionResolvers;

public sealed class ExportCommandOptionsResolverTests
{
    [Fact]
    public void Resolve_WhenTargetIsAtomic_RequiresOnlyAtomicPath()
    {
        var resolved = ExportCommandOptionsResolver.Resolve(
            ExportTarget.Atomic,
            "atomic.csv",
            null,
            "--target",
            "--atomic",
            "--merged");

        Assert.Equal(ExportTarget.Atomic, resolved.Target);
        Assert.Equal("atomic.csv", resolved.AtomicPath);
        Assert.Null(resolved.MergedPath);
    }

    [Fact]
    public void Resolve_WhenTargetIsAtomic_IgnoresMergedPath()
    {
        var resolved = ExportCommandOptionsResolver.Resolve(
            ExportTarget.Atomic,
            "atomic.csv",
            "merged.csv",
            "--target",
            "--atomic",
            "--merged");

        Assert.Equal(ExportTarget.Atomic, resolved.Target);
        Assert.Equal("atomic.csv", resolved.AtomicPath);
        Assert.Null(resolved.MergedPath);
    }

    [Fact]
    public void Resolve_WhenTargetIsMerged_IgnoresAtomicPath()
    {
        var resolved = ExportCommandOptionsResolver.Resolve(
            ExportTarget.Merged,
            "atomic.csv",
            "merged.csv",
            "--target",
            "--atomic",
            "--merged");

        Assert.Equal(ExportTarget.Merged, resolved.Target);
        Assert.Null(resolved.AtomicPath);
        Assert.Equal("merged.csv", resolved.MergedPath);
    }

    [Fact]
    public void Resolve_WhenBothTargetsAreSelected_KeepsBothPaths()
    {
        var resolved = ExportCommandOptionsResolver.Resolve(
            ExportTarget.Atomic | ExportTarget.Merged,
            "atomic.csv",
            "merged.csv",
            "--target",
            "--atomic",
            "--merged");

        Assert.Equal(ExportTarget.Atomic | ExportTarget.Merged, resolved.Target);
        Assert.Equal("atomic.csv", resolved.AtomicPath);
        Assert.Equal("merged.csv", resolved.MergedPath);
    }

    [Fact]
    public void Resolve_WhenSelectedPathIsMissing_ThrowsCommandUsageException()
    {
        var exception = Assert.Throws<FirewallRuleToolkit.Cli.CommandUsageException>(() => ExportCommandOptionsResolver.Resolve(
            ExportTarget.Merged,
            "atomic.csv",
            null,
            "--target",
            "--atomic",
            "--merged"));

        Assert.Contains("--merged", exception.Message, StringComparison.Ordinal);
    }
}
