namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// Composition 層で使う repository 可用性確認と集計の共通処理を提供します。
/// </summary>
internal static class CompositionRepositoryHelper
{
    /// <summary>
    /// 指定した処理を repository 可用性確認後に実行します。
    /// </summary>
    public static TResult ExecuteWhenAvailable<TResult>(
        Func<TResult> action,
        Func<RepositoryUnavailableException, Exception> exceptionFactory,
        params Action[] ensureAvailableActions)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(exceptionFactory);
        EnsureAllAvailableOrThrow(exceptionFactory, ensureAvailableActions);
        return action();
    }

    /// <summary>
    /// 指定した処理を実行し、repository 読み取り例外を指定された例外へ変換します。
    /// </summary>
    public static TResult ExecuteReadOrThrow<TResult>(
        Func<TResult> action,
        Func<RepositoryReadException, Exception> exceptionFactory)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(exceptionFactory);

        try
        {
            return action();
        }
        catch (RepositoryReadException ex)
        {
            throw exceptionFactory(ex);
        }
    }

    /// <summary>
    /// repository が利用可能であることを確認し、不可なら変換後の例外を送出します。
    /// </summary>
    public static void EnsureAvailableOrThrow(
        Action ensureAvailable,
        Func<RepositoryUnavailableException, Exception> exceptionFactory)
    {
        ArgumentNullException.ThrowIfNull(ensureAvailable);
        ArgumentNullException.ThrowIfNull(exceptionFactory);

        try
        {
            ensureAvailable();
        }
        catch (RepositoryUnavailableException ex)
        {
            throw exceptionFactory(ex);
        }
    }

    /// <summary>
    /// 複数 repository の可用性確認を試みます。
    /// </summary>
    public static bool TryEnsureAvailable(params Action[] ensureAvailableActions)
    {
        try
        {
            EnsureAllAvailable(ensureAvailableActions);
            return true;
        }
        catch (RepositoryUnavailableException)
        {
            return false;
        }
    }

    /// <summary>
    /// repository の利用可能性を確認したうえで件数を返します。
    /// </summary>
    public static int CountAvailableItems(IItemCountRepository repository)
    {
        ArgumentNullException.ThrowIfNull(repository);
        repository.EnsureAvailable();
        return repository.Count();
    }

    /// <summary>
    /// 列挙の件数を返します。
    /// </summary>
    public static int CountItems<T>(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        return items.Count();
    }

    private static void EnsureAllAvailableOrThrow(
        Func<RepositoryUnavailableException, Exception> exceptionFactory,
        params Action[] ensureAvailableActions)
    {
        ArgumentNullException.ThrowIfNull(exceptionFactory);

        try
        {
            EnsureAllAvailable(ensureAvailableActions);
        }
        catch (RepositoryUnavailableException ex)
        {
            throw exceptionFactory(ex);
        }
    }

    private static void EnsureAllAvailable(params Action[] ensureAvailableActions)
    {
        ArgumentNullException.ThrowIfNull(ensureAvailableActions);

        foreach (var ensureAvailable in ensureAvailableActions)
        {
            ArgumentNullException.ThrowIfNull(ensureAvailable);
            ensureAvailable();
        }
    }
}
