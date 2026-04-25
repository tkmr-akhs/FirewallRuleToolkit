using FirewallRuleToolkit.Cli.OptionResolvers;
using FirewallRuleToolkit.Config;
using Microsoft.Extensions.Logging;

namespace FirewallRuleToolkit.Tests.Cli.OptionResolvers;

public sealed class LogCommandOptionsResolverTests
{
    [Fact]
    public void ResolveForCommand_WhenConsoleOnlyAndLogFileIsMissing_AllowsMissingLogFile()
    {
        var resolved = LogCommandOptionsResolver.ResolveForCommand(
            LogType.ConsoleOnly,
            null,
            LogLevel.Information,
            "--logtype",
            "--logfile",
            "--loglevel");

        Assert.Equal(LogType.ConsoleOnly, resolved.LogType);
        Assert.Null(resolved.LogFilePath);
        Assert.Equal(LogLevel.Information, resolved.LogLevel);
    }

    [Fact]
    public void ResolveForCommand_WhenFileLoggingAndLogFileIsMissing_ThrowsCommandUsageException()
    {
        var exception = Assert.Throws<FirewallRuleToolkit.Cli.CommandUsageException>(() => LogCommandOptionsResolver.ResolveForCommand(
            LogType.File,
            null,
            LogLevel.Information,
            "--logtype",
            "--logfile",
            "--loglevel"));

        Assert.Contains("--logfile", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolveForLogger_WhenNoLogTypeIsSpecified_AllowsMissingLogFile()
    {
        var resolvedLogFilePath = LogCommandOptionsResolver.ResolveForLogger(
            null,
            null,
            "--logfile");

        Assert.Null(resolvedLogFilePath);
    }
}
