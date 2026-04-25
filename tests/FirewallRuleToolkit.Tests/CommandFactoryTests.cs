using System.CommandLine;
using FirewallRuleToolkit.Config;
using FirewallRuleToolkit.Logging;

namespace FirewallRuleToolkit.Tests;

[Collection("ProgramLogger")]
public sealed class CommandFactoryTests
{
    [Fact]
    public void CreateRootCommand_WhenBuiltMultipleTimes_UsesPerCommandSettingsCache()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var firstConfigPath = Path.Combine(temporaryDirectory, "first.json");
            var secondConfigPath = Path.Combine(temporaryDirectory, "second.json");

            File.WriteAllText(firstConfigPath, "{ \"database\": \"db-one\" }");
            File.WriteAllText(secondConfigPath, "{ \"database\": \"db-two\" }");

            var firstDatabase = ReadDatabaseDefault(FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand(), firstConfigPath);
            var secondDatabase = ReadDatabaseDefault(FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand(), secondConfigPath);

            Assert.Equal("db-one", firstDatabase);
            Assert.Equal("db-two", secondDatabase);
        }
        finally
        {
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void CreateRootCommand_HasDetailedJapaneseHelpDescriptions()
    {
        var rootCommand = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand();

        Assert.NotNull(rootCommand.Description);
        Assert.Contains("一般的な実行順", rootCommand.Description, StringComparison.Ordinal);
        Assert.Contains("4. test", rootCommand.Description, StringComparison.Ordinal);

        var importCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "import");
        Assert.NotNull(importCommand.Description);
        Assert.Contains("Palo Alto Networks", importCommand.Description, StringComparison.Ordinal);

        var atomizeCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "atomize");
        Assert.NotNull(atomizeCommand.Description);
        Assert.Contains("import 済みのセキュリティ ポリシーを対象", atomizeCommand.Description, StringComparison.Ordinal);

        var mergeCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "merge");
        Assert.NotNull(mergeCommand.Description);
        Assert.Contains("Allow 以外のルール", mergeCommand.Description, StringComparison.Ordinal);
        Assert.Contains("IP プロトコル番号", mergeCommand.Description, StringComparison.Ordinal);
        Assert.Contains("wkpthreshold 未満", mergeCommand.Description, StringComparison.Ordinal);

        var testCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "test");
        Assert.NotNull(testCommand.Description);
        Assert.Contains("shadowed", testCommand.Description, StringComparison.Ordinal);
        Assert.Contains("warning", testCommand.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateRootCommand_HasExpandedGlobalOptionDescriptions()
    {
        var rootCommand = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand();

        var databaseOption = Assert.Single(
            rootCommand.Options,
            static option => option.ToString().Contains("--database", StringComparison.Ordinal));
        var logLevelOption = Assert.Single(
            rootCommand.Options,
            static option => option.ToString().Contains("--loglevel", StringComparison.Ordinal));

        Assert.NotNull(databaseOption.Description);
        Assert.Contains("SQLite", databaseOption.Description, StringComparison.Ordinal);
        Assert.NotNull(logLevelOption.Description);
        Assert.Contains("Debug", logLevelOption.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateRootCommand_MergeCommandHasWellKnownPortOptions()
    {
        var rootCommand = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand();
        var mergeCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "merge");

        Assert.Contains(
            mergeCommand.Options,
            static option => option.ToString().Contains("--wkport", StringComparison.Ordinal));
        Assert.Contains(
            mergeCommand.Options,
            static option => option.ToString().Contains("--wkpthreshold", StringComparison.Ordinal));

        var wkPortOption = Assert.Single(
            mergeCommand.Options,
            static option => option.ToString().Contains("--wkport", StringComparison.Ordinal));
        var wkpthresholdOption = Assert.Single(
            mergeCommand.Options,
            static option => option.ToString().Contains("--wkpthreshold", StringComparison.Ordinal));

        Assert.NotNull(wkPortOption.Description);
        Assert.Contains("よく使う宛先ポート", wkPortOption.Description, StringComparison.Ordinal);
        Assert.NotNull(wkpthresholdOption.Description);
        Assert.Contains("すべて wkport に含まれ", wkpthresholdOption.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateRootCommand_MergeCommandHasHighSimilarityPercentOption()
    {
        var rootCommand = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand();
        var mergeCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "merge");

        var hsPercentOption = Assert.Single(
            mergeCommand.Options,
            static option => option.ToString().Contains("--hspercent", StringComparison.Ordinal));

        Assert.NotNull(hsPercentOption.Description);
        Assert.Contains("設定ファイルまたはコマンドライン", hsPercentOption.Description, StringComparison.Ordinal);
        Assert.Contains("1 から 100", hsPercentOption.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateRootCommand_MergeCommandReadsHsPercentDefaultFromConfig()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(configPath, "{ \"merge\": { \"hspercent\": 85 } }");

            var hsPercent = ReadMergeHsPercentDefault(FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand(), configPath);

            Assert.Equal((uint)85, hsPercent);
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void CreateRootCommand_MergeCommandFailsWhenHsPercentIsMissing()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(
                configPath,
                """
                {
                  "database": "db",
                  "logtype": "ConsoleOnly",
                  "logfile": "app.log",
                  "loglevel": "Information",
                  "merge": { }
                }
                """);

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse(["merge", "--config", configPath])
                .Invoke();

            Assert.Equal(1, exitCode);
        }
        finally
        {
            ProgramLogger.Dispose();
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void CreateRootCommand_WhenConfigIsMissing_ExplicitFileLoggerStillWritesToFile()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var missingConfigPath = Path.Combine(temporaryDirectory, "missing.json");
            var logPath = Path.Combine(temporaryDirectory, "app.log");
            var databaseDirectory = Path.Combine(temporaryDirectory, "db");

            ProgramLogger.Dispose();

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse([
                    "stat",
                    "--config", missingConfigPath,
                    "--database", databaseDirectory,
                    "--logtype", "File",
                    "--logfile", logPath,
                    "--loglevel", "Debug"
                ])
                .Invoke();

            ProgramLogger.Dispose();

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(logPath));
            Assert.Contains("command: stat", ReadAllTextShared(logPath), StringComparison.Ordinal);
        }
        finally
        {
            ProgramLogger.Dispose();
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void CreateRootCommand_WhenEventLogIsSelected_ReturnsCommandError()
    {
        try
        {
            ProgramLogger.Dispose();

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse([
                    "stat",
                    "--database", "db",
                    "--logtype", "EventLog",
                    "--logfile", "app.log",
                    "--loglevel", "Information"
                ])
                .Invoke();

            Assert.Equal(1, exitCode);
        }
        finally
        {
            ProgramLogger.Dispose();
        }
    }

    [Fact]
    public void CreateRootCommand_WhenFileLoggingIsMissingPath_ReturnsCommandError()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(
                configPath,
                """
                {
                  "database": "db",
                  "logtype": "File",
                  "loglevel": "Information",
                  "stat": { }
                }
                """);

            ProgramLogger.Dispose();

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse([
                    "stat",
                    "--config", configPath
                ])
                .Invoke();

            Assert.Equal(1, exitCode);
        }
        finally
        {
            ProgramLogger.Dispose();
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void CreateRootCommand_WhenConsoleOnlyAndLogFileIsMissing_ReturnsSuccess()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(
                configPath,
                """
                {
                  "database": "db",
                  "logtype": "ConsoleOnly",
                  "loglevel": "Information",
                  "stat": { }
                }
                """);

            ProgramLogger.Dispose();

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse(["stat", "--config", configPath])
                .Invoke();

            Assert.Equal(0, exitCode);
        }
        finally
        {
            ProgramLogger.Dispose();
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void CreateRootCommand_WhenConfigJsonIsInvalid_ReadingDefaultValueThrowsCommandUsageException()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(configPath, "{ invalid json");

            var exception = Assert.Throws<FirewallRuleToolkit.Cli.CommandUsageException>(() =>
                ReadDatabaseDefault(FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand(), configPath));

            Assert.Contains("設定ファイルの JSON を解析できませんでした", exception.Message, StringComparison.Ordinal);
            Assert.Contains(configPath, exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    [Fact]
    public void CreateRootCommand_WhenConfigJsonIsInvalidAndCommandOptionsAreExplicit_ReturnsCommandError()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            var configPath = Path.Combine(temporaryDirectory, "settings.json");
            File.WriteAllText(configPath, "{ invalid json");

            ProgramLogger.Dispose();

            var exitCode = FirewallRuleToolkit.Cli.CommandFactory.CreateRootCommand()
                .Parse([
                    "stat",
                    "--config", configPath,
                    "--database", "db",
                    "--logtype", "ConsoleOnly",
                    "--logfile", "ignored.log",
                    "--loglevel", "Information"
                ])
                .Invoke();

            Assert.Equal(1, exitCode);
        }
        finally
        {
            ProgramLogger.Dispose();
            DeleteDirectoryWithRetry(temporaryDirectory);
        }
    }

    private static string? ReadDatabaseDefault(RootCommand rootCommand, string configPath)
    {
        var databaseOption = Assert.Single(
            rootCommand.Options,
            static option => option.ToString().Contains("--" + nameof(Settings.Database).ToLowerInvariant(), StringComparison.Ordinal));
        var parseResult = rootCommand.Parse(["--config", configPath]);
        return parseResult.GetValue(Assert.IsType<Option<string?>>(databaseOption));
    }

    private static uint? ReadMergeHsPercentDefault(RootCommand rootCommand, string configPath)
    {
        var mergeCommand = Assert.Single(rootCommand.Subcommands, static command => command.Name == "merge");
        var hsPercentOption = Assert.Single(
            mergeCommand.Options,
            static option => option.ToString().Contains("--hspercent", StringComparison.Ordinal));
        var parseResult = rootCommand.Parse(["merge", "--config", configPath]);
        return parseResult.GetValue(Assert.IsType<Option<uint?>>(hsPercentOption));
    }

    private static void DeleteDirectoryWithRetry(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        const int maxAttempts = 5;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException)
            {
                if (attempt == maxAttempts)
                {
                    return;
                }

                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException)
            {
                if (attempt == maxAttempts)
                {
                    return;
                }

                Thread.Sleep(50);
            }
        }
    }

    private static string ReadAllTextShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
