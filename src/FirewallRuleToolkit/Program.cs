namespace FirewallRuleToolkit;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            var rootCommand = Cli.CommandFactory.CreateRootCommand();

            var normalizedArgs = NormalizeArguments(args);

            var parseResult = rootCommand.Parse(normalizedArgs);

            return parseResult.Invoke();
        }
        catch (FirewallRuleToolkit.Cli.CommandUsageException ex)
        {
            ProgramLogger.GetLogger(null, null, null).LogError("{ErrorMessage}", ex.Message);
            return 1;
        }
        catch (FirewallRuleToolkit.App.ApplicationUsageException ex)
        {
            ProgramLogger.GetLogger(null, null, null).LogError("{ErrorMessage}", ex.Message);
            return 1;
        }
        catch (Exception ex)
        {
            var logger = ProgramLogger.GetLogger(null, null, null);
            logger.LogError("Unhandled exception occurred. {ExceptionSummary}", ExceptionLogFormatter.Summarize(ex));
            logger.LogDebug(ex, "Unhandled exception details.");
            return 1;
        }
        finally
        {
            ProgramLogger.Dispose();
        }
    }

    internal static string[] NormalizeArguments(IEnumerable<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Select(NormalizeArgument).ToArray();
    }

    private static string NormalizeArgument(string arg)
    {
        if (!arg.StartsWith("--", StringComparison.Ordinal))
        {
            return arg;
        }

        var separatorIndex = arg.IndexOf('=');
        if (separatorIndex < 0)
        {
            return arg.ToLowerInvariant();
        }

        return string.Concat(
            arg.AsSpan(0, separatorIndex).ToString().ToLowerInvariant(),
            arg.AsSpan(separatorIndex));
    }
}
