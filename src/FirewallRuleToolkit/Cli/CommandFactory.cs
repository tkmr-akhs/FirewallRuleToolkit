using System.CommandLine;
using System.CommandLine.Parsing;
using System.Text.Json;
using FirewallRuleToolkit.App.Composition;
using FirewallRuleToolkit.Cli.OptionResolvers;
using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.Cli;

/// <summary>
/// CLI コマンドとオプションを構築します。
/// </summary>
internal static class CommandFactory
{
    private const string DefaultConfigFileName = "fwrule-tool.json";

    /// <summary>
    /// ルート コマンドを生成します。
    /// </summary>
    /// <returns>生成されたルート コマンド。</returns>
    public static RootCommand CreateRootCommand()
    {
        var settingsCache = new SettingsCache();
        var commonOptions = CreateCommonCliOptions(settingsCache);

        var rootCommand = new RootCommand(CommandDescriptions.Root);
        rootCommand.Add(commonOptions.ConfigOption);
        rootCommand.Add(commonOptions.DatabaseOption);
        rootCommand.Add(commonOptions.LogTypeOption);
        rootCommand.Add(commonOptions.LogFileOption);
        rootCommand.Add(commonOptions.LogLevelOption);
        rootCommand.Add(CreateImportCommand(settingsCache, commonOptions));
        rootCommand.Add(CreateExportCommand(settingsCache, commonOptions));
        rootCommand.Add(CreateAtomizeCommand(settingsCache, commonOptions));
        rootCommand.Add(CreateMergeCommand(settingsCache, commonOptions));
        rootCommand.Add(CreateTestCommand(commonOptions));
        rootCommand.Add(CreateStatCommand(commonOptions));

        rootCommand.SetAction(CreateRootAction(commonOptions));

        return rootCommand;
    }

    private static Command CreateImportCommand(
        SettingsCache settingsCache,
        CommonCliOptions commonOptions)
    {
        var encodingOption = new Option<string?>(GetOptionName(nameof(Settings.Import.Encoding)))
        {
            Description = "入力 CSV の文字コード。utf-8 や shift_jis など Encoding.GetEncoding で解決できる名前を指定します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.Encoding)
        };

        var withBomOption = new Option<bool?>(GetOptionName(nameof(Settings.Import.WithBom)))
        {
            Description = "UTF-8 入力 CSV を BOM 付きとして扱う場合に指定します。設定ファイルでは true / false で指定できます。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.WithBom)
        };

        var securityPoliciesOption = new Option<string?>(GetOptionName(nameof(Settings.Import.SecurityPolicies)))
        {
            Description = "Palo Alto Networks 形式のセキュリティ ポリシー CSV ファイルのパスです。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.SecurityPolicies)
        };

        var addressesOption = new Option<string?>(GetOptionName(nameof(Settings.Import.Addresses)))
        {
            Description = "Palo Alto Networks 形式のアドレス オブジェクト CSV ファイルのパスです。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.Addresses)
        };

        var addressGroupsOption = new Option<string?>(GetOptionName(nameof(Settings.Import.AddressGroups)))
        {
            Description = "Palo Alto Networks 形式のアドレス グループ CSV ファイルのパスです。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.AddressGroups)
        };

        var servicesOption = new Option<string?>(GetOptionName(nameof(Settings.Import.Services)))
        {
            Description = "Palo Alto Networks 形式のサービス オブジェクト CSV ファイルのパスです。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.Services)
        };

        var serviceGroupsOption = new Option<string?>(GetOptionName(nameof(Settings.Import.ServiceGroups)))
        {
            Description = "Palo Alto Networks 形式のサービス グループ CSV ファイルのパスです。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Import.ServiceGroups)
        };

        var importCommand = new Command("import", CommandDescriptions.Import);
        importCommand.Add(encodingOption);
        importCommand.Add(withBomOption);
        importCommand.Add(securityPoliciesOption);
        importCommand.Add(addressesOption);
        importCommand.Add(addressGroupsOption);
        importCommand.Add(servicesOption);
        importCommand.Add(serviceGroupsOption);

        importCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            var encoding = CommandOptionValueResolver.RequireValue(parseResult.GetValue(encodingOption), encodingOption.Name);
            var withBom = CommandOptionValueResolver.RequireValue(parseResult.GetValue(withBomOption), withBomOption.Name);
            var securityPoliciesPath = CommandOptionValueResolver.RequireValue(parseResult.GetValue(securityPoliciesOption), securityPoliciesOption.Name);
            var addressesPath = CommandOptionValueResolver.RequireValue(parseResult.GetValue(addressesOption), addressesOption.Name);
            var addressGroupsPath = CommandOptionValueResolver.RequireValue(parseResult.GetValue(addressGroupsOption), addressGroupsOption.Name);
            var servicesPath = CommandOptionValueResolver.RequireValue(parseResult.GetValue(servicesOption), servicesOption.Name);
            var serviceGroupsPath = CommandOptionValueResolver.RequireValue(parseResult.GetValue(serviceGroupsOption), serviceGroupsOption.Name);
            LogCommandStart(
                context,
                parseResult,
                commonOptions,
                importCommand.Name,
                ("import.encoding", encoding),
                ("import.withbom", withBom),
                ("import.securitypolicies", securityPoliciesPath),
                ("import.addresses", addressesPath),
                ("import.addressgroups", addressGroupsPath),
                ("import.services", servicesPath),
                ("import.servicegroups", serviceGroupsPath));

            return ImportComposition.Run(
                context.DatabaseDirectory,
                EncodingOptionResolver.Resolve(encoding, withBom),
                securityPoliciesPath,
                addressesPath,
                addressGroupsPath,
                servicesPath,
                serviceGroupsPath);
        }));

        return importCommand;
    }

    private static Command CreateAtomizeCommand(
        SettingsCache settingsCache,
        CommonCliOptions commonOptions)
    {
        var thresholdOption = new Option<int?>(GetOptionName(nameof(Settings.Atomize.Threshold)))
        {
            Description = "アドレス範囲やポート範囲を単一値へ展開するしきい値です。要素数がこの値以上なら範囲のまま保持します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Atomize.Threshold)
        };

        var atomizeCommand = new Command("atomize", CommandDescriptions.Atomize);
        atomizeCommand.Add(thresholdOption);
        atomizeCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            var threshold = AtomizeCommandOptionsResolver.ResolveThreshold(
                parseResult.GetValue(thresholdOption),
                thresholdOption.Name);

            LogCommandStart(
                context,
                parseResult,
                commonOptions,
                atomizeCommand.Name,
                ("atomize.threshold", threshold));
            return AtomizeComposition.Run(context.DatabaseDirectory, threshold);
        }));

        return atomizeCommand;
    }

    private static Command CreateMergeCommand(
        SettingsCache settingsCache,
        CommonCliOptions commonOptions)
    {
        var wkPortOption = new Option<string?>(GetOptionName(nameof(Settings.Merge.WkPort)))
        {
            Description = "よく使う宛先ポートの一覧です。\"80,443\" のようにカンマ区切りで指定します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Merge.WkPort)
        };

        var wkpThresholdOption = new Option<uint?>(GetOptionName(nameof(Settings.Merge.WkpThreshold)))
        {
            Description = "宛先アドレス集約を抑止する閾値です。宛先ポートがすべて wkport に含まれ、かつ、その個数がこの値未満のときだけ宛先アドレスをまとめません。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Merge.WkpThreshold)
        };

        var hsPercentOption = new Option<uint?>(GetOptionName(nameof(Settings.Merge.HsPercent)))
        {
            Description = "高一致率再編成で使う類似度しきい値 (パーセント) です。設定ファイルまたはコマンドライン オプションで指定し、1 から 100 の範囲で指定します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Merge.HsPercent)
        };

        var mergeCommand = new Command("merge", CommandDescriptions.Merge);
        mergeCommand.Add(wkPortOption);
        mergeCommand.Add(wkpThresholdOption);
        mergeCommand.Add(hsPercentOption);
        mergeCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            var mergeOptions = MergeCommandOptionsResolver.Resolve(
                parseResult.GetValue(wkPortOption),
                parseResult.GetValue(wkpThresholdOption),
                parseResult.GetValue(hsPercentOption),
                hsPercentOption.Name);

            LogCommandStart(
                context,
                parseResult,
                commonOptions,
                mergeCommand.Name,
                ("merge.wkport", mergeOptions.WkPortLogValue),
                ("merge.wkpthreshold", mergeOptions.WkpThreshold),
                ("merge.hspercent", mergeOptions.HsPercent));
            return MergeComposition.Run(
                context.DatabaseDirectory,
                mergeOptions.HsPercent,
                mergeOptions.WellKnownDestinationPorts,
                mergeOptions.WkpThreshold);
        }));

        return mergeCommand;
    }

    private static Command CreateExportCommand(
        SettingsCache settingsCache,
        CommonCliOptions commonOptions)
    {
        var encodingOption = new Option<string?>(GetOptionName(nameof(Settings.Export.Encoding)))
        {
            Description = "出力 CSV の文字コード。utf-8 や shift_jis など Encoding.GetEncoding で解決できる名前を指定します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Export.Encoding)
        };

        var withBomOption = new Option<bool?>(GetOptionName(nameof(Settings.Export.WithBom)))
        {
            Description = "UTF-8 出力 CSV を BOM 付きで書き出す場合に指定します。設定ファイルでは true / false で指定できます。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Export.WithBom)
        };

        var targetOption = new Option<ExportTarget?>(GetOptionName(nameof(Settings.Export.Target)))
        {
            Description = "出力対象。Atomic、Merged、または両方を指定します。設定ファイルでは \"Atomic, Merged\" の形式も使えます。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Export.Target)
        };

        var atomicOption = new Option<string?>(GetOptionName(nameof(Settings.Export.Atomic)))
        {
            Description = "atomize 結果を出力する CSV ファイルのパスです。target に Atomic を含む場合に使用します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Export.Atomic)
        };

        var mergedOption = new Option<string?>(GetOptionName(nameof(Settings.Export.Merged)))
        {
            Description = "merge 結果を出力する CSV ファイルのパスです。target に Merged を含む場合に使用します。",
            DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, commonOptions.ConfigOption, settings => settings.Export.Merged)
        };

        var exportCommand = new Command("export", CommandDescriptions.Export);
        exportCommand.Add(encodingOption);
        exportCommand.Add(withBomOption);
        exportCommand.Add(targetOption);
        exportCommand.Add(atomicOption);
        exportCommand.Add(mergedOption);

        exportCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            var encoding = CommandOptionValueResolver.RequireValue(parseResult.GetValue(encodingOption), encodingOption.Name);
            var withBom = CommandOptionValueResolver.RequireValue(parseResult.GetValue(withBomOption), withBomOption.Name);
            var exportOptions = ExportCommandOptionsResolver.Resolve(
                parseResult.GetValue(targetOption),
                parseResult.GetValue(atomicOption),
                parseResult.GetValue(mergedOption),
                targetOption.Name,
                atomicOption.Name,
                mergedOption.Name);

            LogCommandStart(
                context,
                parseResult,
                commonOptions,
                exportCommand.Name,
                ("export.encoding", encoding),
                ("export.withbom", withBom),
                ("export.target", exportOptions.Target),
                ("export.atomic", exportOptions.AtomicPath),
                ("export.merged", exportOptions.MergedPath));

            return ExportComposition.Run(
                context.DatabaseDirectory,
                EncodingOptionResolver.Resolve(encoding, withBom),
                exportOptions.Target,
                exportOptions.AtomicPath,
                exportOptions.MergedPath);
        }));

        return exportCommand;
    }

    private static Command CreateTestCommand(
        CommonCliOptions commonOptions)
    {
        var testCommand = new Command("test", CommandDescriptions.Test);
        testCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            LogCommandStart(context, parseResult, commonOptions, testCommand.Name);

            return TestComposition.Run(context.DatabaseDirectory);
        }));

        return testCommand;
    }

    private static Command CreateStatCommand(
        CommonCliOptions commonOptions)
    {
        var statCommand = new Command("stat", CommandDescriptions.Stat);
        statCommand.SetAction(CreateLoggedAction(commonOptions, parseResult =>
        {
            var context = CommandContextFactory.Create(parseResult, commonOptions);
            LogCommandStart(context, parseResult, commonOptions, statCommand.Name);

            return StatComposition.Run(context.DatabaseDirectory);
        }));

        return statCommand;
    }

    private static string GetOptionName(string optionName)
    {
        return $"--{optionName}".ToLowerInvariant();
    }

    private static Func<ParseResult, int> CreateLoggedAction(
        CommonCliOptions commonOptions,
        Func<ParseResult, int> action)
    {
        ArgumentNullException.ThrowIfNull(commonOptions);
        ArgumentNullException.ThrowIfNull(action);

        return parseResult => ExecuteLoggedAction(
            parseResult,
            commonOptions,
            parseResult.CommandResult.Command.Name,
            _ => action(parseResult));
    }

    private static Func<ParseResult, int> CreateRootAction(CommonCliOptions commonOptions)
    {
        ArgumentNullException.ThrowIfNull(commonOptions);

        return parseResult => ExecuteLoggedAction(
            parseResult,
            commonOptions,
            "(root)",
            logger =>
            {
                logger.LogInformation("command: (root)");
                LogCommonOptions(
                    logger,
                    parseResult,
                    commonOptions,
                    parseResult.GetValue(commonOptions.DatabaseOption),
                    parseResult.GetValue(commonOptions.LogTypeOption),
                    parseResult.GetValue(commonOptions.LogFileOption),
                    parseResult.GetValue(commonOptions.LogLevelOption));
                logger.LogError("サブコマンドを指定してください。使い方の詳細は --help を参照してください。");
                return 1;
            });
    }

    private static int ExecuteLoggedAction(
        ParseResult parseResult,
        CommonCliOptions commonOptions,
        string commandName,
        Func<ILogger, int> action)
    {
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(commandName);
        ArgumentNullException.ThrowIfNull(action);

        ILogger? logger = null;

        try
        {
            ValidateSettingsFileIfPresent(parseResult, commonOptions);
            logger = CommandContextFactory.CreateLogger(parseResult, commonOptions);
            var exitCode = action(logger);
            var status = exitCode == 0 ? "succeeded" : "failed";
            logger.LogInformation("finished. command: {CommandName}, status: {Status}, exitCode: {ExitCode}", commandName, status, exitCode);
            return exitCode;
        }
        catch (CommandUsageException ex)
        {
            logger ??= ProgramLogger.GetLogger(null, null, null);
            logger.LogError("{ErrorMessage}", ex.Message);
            const int exitCode = 1;
            const string status = "failed";
            logger.LogInformation("finished. command: {CommandName}, status: {Status}, exitCode: {ExitCode}", commandName, status, exitCode);
            return exitCode;
        }
        catch (FirewallRuleToolkit.App.ApplicationUsageException ex)
        {
            logger ??= ProgramLogger.GetLogger(null, null, null);
            logger.LogError("{ErrorMessage}", ex.Message);
            const int exitCode = 1;
            const string status = "failed";
            logger.LogInformation("finished. command: {CommandName}, status: {Status}, exitCode: {ExitCode}", commandName, status, exitCode);
            return exitCode;
        }
        catch (Exception ex)
        {
            logger ??= ProgramLogger.GetLogger(null, null, null);
            logger.LogError("An unknown error occurred. {ExceptionSummary}", ExceptionLogFormatter.Summarize(ex));
            logger.LogDebug(ex, "Unknown error details.");
            const int exitCode = 1;
            const string status = "failed";
            logger.LogInformation("finished. command: {CommandName}, status: {Status}, exitCode: {ExitCode}", commandName, status, exitCode);
            return exitCode;
        }
    }

    private static CommonCliOptions CreateCommonCliOptions(SettingsCache settingsCache)
    {
        // エントリ ポイント Program.cs で、「--」で始まる長いオプション名を ToLowerInvariant しているため、
        // ここで大文字を含むフル オプション名を指定すると、動作しなくなることに要注意。
        // (すべて小文字のフル オプション名とする必要がある)
        // (1 文字の短縮名には影響しないため、大文字小文字の両方が使用可能)
        var configOption = new Option<string>("--config")
        {
            Description = "設定ファイル JSON のパス。未指定時はカレント ディレクトリの fwrule-tool.json を読み込みます。",
            Recursive = true,
            DefaultValueFactory = _ => DefaultConfigFileName
        };

        return new CommonCliOptions
        {
            ConfigOption = configOption,
            DatabaseOption = new Option<string?>(GetOptionName(nameof(Settings.Database)))
            {
                Description = "作業用 SQLite データベースを保存するフォルダー。全サブコマンドで共有します。",
                Recursive = true,
                DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, configOption, settings => settings.Database)
            },
            LogTypeOption = new Option<LogType?>(GetOptionName(nameof(Settings.LogType)))
            {
                Description = "ログの出力先。ConsoleOnly / File を選択します。EventLog は未実装です。",
                Recursive = true,
                DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, configOption, settings => settings.LogType)
            },
            LogFileOption = new Option<string?>(GetOptionName(nameof(Settings.LogFile)))
            {
                Description = "ログ ファイルの出力先。logtype に File を指定した場合に使用します。ConsoleOnly では省略できます。",
                Recursive = true,
                DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, configOption, settings => settings.LogFile)
            },
            LogLevelOption = new Option<LogLevel?>(GetOptionName(nameof(Settings.LogLevel)))
            {
                Description = "出力する最小ログ レベル。調査時は Debug または Trace が便利です。",
                Recursive = true,
                DefaultValueFactory = CreateSettingsDefaultValueFactory(settingsCache, configOption, settings => settings.LogLevel)
            }
        };
    }

    private static void ValidateSettingsFileIfPresent(
        ParseResult parseResult,
        CommonCliOptions commonOptions)
    {
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);

        var configPath = parseResult.GetValue(commonOptions.ConfigOption);
        if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath))
        {
            return;
        }

        _ = LoadSettings(configPath);
    }

    private static void LogCommandStart(
        CommandContext context,
        ParseResult parseResult,
        CommonCliOptions commonOptions,
        string commandName,
        params (string Name, object? Value)[] details)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(commandName);

        context.Logger.LogInformation("command: {CommandName}", commandName);
        LogCommonOptions(
            context.Logger,
            parseResult,
            commonOptions,
            context.DatabaseDirectory,
            context.LogType,
            context.LogFilePath,
            context.LogLevel);

        foreach (var (name, value) in details)
        {
            context.Logger.LogDebug("{DetailName}: {DetailValue}", name, value);
        }
    }

    private static void LogCommonOptions(
        ILogger logger,
        ParseResult parseResult,
        CommonCliOptions commonOptions,
        string? databaseDirectory,
        LogType? logType,
        string? logFilePath,
        LogLevel? logLevel)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(commonOptions);

        logger.LogDebug("config: {ConfigPath}", parseResult.GetValue(commonOptions.ConfigOption));
        logger.LogDebug("database: {DatabaseDirectory}", databaseDirectory);
        logger.LogDebug("logtype: {LogType}", logType);
        logger.LogDebug("logfile: {LogFilePath}", logFilePath);
        logger.LogDebug("loglevel: {LogLevel}", logLevel);
    }

    private static Func<ArgumentResult, T?> CreateSettingsDefaultValueFactory<T>(
        SettingsCache settingsCache,
        Option<string> configOption,
        Func<Settings, T?> selector)
    {
        return parseResult =>
        {
            var settings = settingsCache.GetOrLoad(parseResult, configOption);
            return settings is null ? default : selector(settings);
        };
    }

    private static Settings? LoadSettingsFromParseResult(
        ArgumentResult parseResult,
        Option<string> configOption)
    {
        var configPath = parseResult.GetValue(configOption) ?? DefaultConfigFileName;
        return LoadSettings(configPath);
    }

    private static Settings? LoadSettings(string path)
    {
        try
        {
            return new JsonToolSettingsSource()
                .LoadAsync(path, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
        }
        catch (IOException)
        {
            ProgramLogger.GetLogger(null, null, null)
                .LogWarning("設定ファイルを読み込めませんでした。パス: \"{SettingsPath}\"", path);
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            ProgramLogger.GetLogger(null, null, null)
                .LogWarning("設定ファイルへのアクセスが拒否されました。パス: \"{SettingsPath}\".", path);
            return null;
        }
        catch (JsonException ex)
        {
            throw CreateInvalidSettingsException(path, ex);
        }
        catch (NotSupportedException ex)
        {
            throw CreateInvalidSettingsException(path, ex);
        }
    }

    private static CommandUsageException CreateInvalidSettingsException(string path, Exception exception)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(exception);

        return new CommandUsageException(
            $"設定ファイルの JSON を解析できませんでした。パス: \"{path}\". {exception.Message}");
    }

    private sealed class SettingsCache
    {
        private Settings? settings;
        private bool isLoaded;

        public Settings? GetOrLoad(ArgumentResult parseResult, Option<string> configOption)
        {
            ArgumentNullException.ThrowIfNull(parseResult);
            ArgumentNullException.ThrowIfNull(configOption);

            if (!isLoaded)
            {
                settings = LoadSettingsFromParseResult(parseResult, configOption);
                isLoaded = true;
            }

            return settings;
        }
    }
}
