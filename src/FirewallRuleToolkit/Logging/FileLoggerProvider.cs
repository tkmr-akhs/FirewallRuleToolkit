using System.Collections.Concurrent;

namespace FirewallRuleToolkit.Logging;

/// <summary>
/// ファイルへ書き出すロガーを提供します。
/// </summary>
internal sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter writer;
    private readonly ConcurrentDictionary<string, FileLogger> loggers = new(StringComparer.Ordinal);
    private bool disposed;

    /// <summary>
    /// ファイルへ書き出すロガーを提供するクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">ログ ファイル パス。</param>
    public FileLoggerProvider(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var directoryPath = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directoryPath))
        {
            Directory.CreateDirectory(directoryPath);
        }

        writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
        {
            AutoFlush = true
        };
    }

    /// <summary>
    /// 指定カテゴリ用のロガーを生成または取得します。
    /// </summary>
    /// <param name="categoryName">カテゴリ名。</param>
    /// <returns>ロガー。</returns>
    public ILogger CreateLogger(string categoryName)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return loggers.GetOrAdd(categoryName, name => new FileLogger(name, writer));
    }

    /// <summary>
    /// 使用中のリソースを破棄します。
    /// </summary>
    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        writer.Dispose();
    }
}
