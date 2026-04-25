using FirewallRuleToolkit.Config;

namespace FirewallRuleToolkit.App.UseCases;

/// <summary>
/// export サブコマンドの処理を提供します。
/// </summary>
internal static class ExportUseCase
{
    /// <summary>
    /// データベースから CSV へ各種情報を出力します。
    /// </summary>
    /// <param name="target">出力対象。</param>
    /// <param name="atomicSource">atomic 出力元。</param>
    /// <param name="atomicDestination">atomic 出力先。</param>
    /// <param name="mergedSource">merged 出力元。</param>
    /// <param name="mergedDestination">merged 出力先。</param>
    /// <returns>終了コード。</returns>
    public static int Execute(
        ExportTarget target,
        IReadRepository<AtomicSecurityPolicy>? atomicSource,
        IWriteRepository<AtomicSecurityPolicy>? atomicDestination,
        IReadRepository<MergedSecurityPolicy>? mergedSource,
        IWriteRepository<MergedSecurityPolicy>? mergedDestination)
    {
        if (target == ExportTarget.None)
        {
            throw new ApplicationUsageException("Select at least one export target.");
        }

        if (target.HasFlag(ExportTarget.Atomic))
        {
            EnsureExportReady(
                atomicSource,
                atomicDestination,
                nameof(atomicSource),
                nameof(atomicDestination),
                static _ => new ApplicationUsageException("Atomize has not been executed. Please run atomize first."));
        }

        if (target.HasFlag(ExportTarget.Merged))
        {
            EnsureExportReady(
                mergedSource,
                mergedDestination,
                nameof(mergedSource),
                nameof(mergedDestination),
                static _ => new ApplicationUsageException("Merge has not been executed. Please run merge first."));
        }

        if (target.HasFlag(ExportTarget.Atomic))
        {
            ExportRequired(atomicSource!, atomicDestination!);
        }

        if (target.HasFlag(ExportTarget.Merged))
        {
            ExportRequired(mergedSource!, mergedDestination!);
        }

        return 0;
    }

    private static void EnsureExportReady<T>(
        IReadRepository<T>? source,
        IWriteRepository<T>? destination,
        string sourceArgumentName,
        string destinationArgumentName,
        Func<RepositoryUnavailableException, Exception> unavailableExceptionFactory)
    {
        ArgumentNullException.ThrowIfNull(unavailableExceptionFactory);

        if (source is null)
        {
            throw new InvalidOperationException($"{sourceArgumentName} must be provided for the selected export target.");
        }

        if (destination is null)
        {
            throw new InvalidOperationException($"{destinationArgumentName} must be provided for the selected export target.");
        }

        try
        {
            source.EnsureAvailable();
        }
        catch (RepositoryUnavailableException ex)
        {
            throw unavailableExceptionFactory(ex);
        }
    }

    private static void ExportRequired<T>(IReadRepository<T> source, IWriteRepository<T> destination)
    {
        destination.ReplaceAll(source.GetAll());
    }
}
