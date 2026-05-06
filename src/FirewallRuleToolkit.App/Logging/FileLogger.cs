namespace FirewallRuleToolkit.Logging;

/// <summary>
/// ファイルへログを書き出すロガーです。
/// </summary>
internal sealed class FileLogger(string categoryName, StreamWriter writer) : ILogger
{
    private readonly string categoryName = categoryName;
    private readonly StreamWriter writer = writer;
    private static readonly object SyncRoot = new();

    /// <summary>
    /// スコープを開始します。
    /// </summary>
    /// <typeparam name="TState">スコープ状態の型。</typeparam>
    /// <param name="state">スコープ状態。</param>
    /// <returns>破棄可能なスコープ。未使用の場合は <see langword="null"/>。</returns>
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return null;
    }

    /// <summary>
    /// 指定ログ レベルが有効かどうかを判定します。
    /// </summary>
    /// <param name="logLevel">判定するログ レベル。</param>
    /// <returns>有効な場合は <see langword="true"/>。</returns>
    public bool IsEnabled(LogLevel logLevel)
    {
        return logLevel != LogLevel.None;
    }

    /// <summary>
    /// ログを書き出します。
    /// </summary>
    /// <typeparam name="TState">状態オブジェクトの型。</typeparam>
    /// <param name="logLevel">ログ レベル。</param>
    /// <param name="eventId">イベント ID。</param>
    /// <param name="state">状態オブジェクト。</param>
    /// <param name="exception">例外情報。</param>
    /// <param name="formatter">メッセージ整形関数。</param>
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        if (!IsEnabled(logLevel))
        {
            return;
        }

        var message = formatter(state, exception);
        if (string.IsNullOrEmpty(message) && exception is null)
        {
            return;
        }

        var timestamp = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz");

        lock (SyncRoot)
        {
            writer.Write(timestamp);
            writer.Write(' ');
            writer.Write('[');
            writer.Write(logLevel);
            writer.Write("] ");
            writer.Write(categoryName);
            writer.Write(": ");
            writer.WriteLine(message);

            if (exception is not null)
            {
                writer.WriteLine(exception);
            }
        }
    }
}
