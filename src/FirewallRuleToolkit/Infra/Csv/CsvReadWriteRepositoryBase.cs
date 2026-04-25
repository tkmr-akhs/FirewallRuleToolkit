using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv;

/// <summary>
/// CSV の read/write リポジトリ実装の基底クラスです。
/// </summary>
/// <typeparam name="T">永続化対象の型。</typeparam>
public abstract class CsvReadWriteRepositoryBase<T> : IReadWriteRepository<T>
{
    private readonly string path;
    private readonly CsvOptions options;
    private readonly IList<string> headers;
    private readonly Func<IReadOnlyDictionary<string, string>, T> readRow;
    private readonly Func<T, IList<string>> writeRow;

    /// <summary>
    /// CSV の read/write リポジトリ実装の基底クラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="headers">ヘッダー定義。</param>
    /// <param name="readRow">1 行からエンティティへ変換する関数。</param>
    /// <param name="writeRow">エンティティから 1 行へ変換する関数。</param>
    protected CsvReadWriteRepositoryBase(
        string path,
        CsvOptions options,
        IList<string> headers,
        Func<IReadOnlyDictionary<string, string>, T> readRow,
        Func<T, IList<string>> writeRow)
    {
        this.path = path ?? throw new ArgumentNullException(nameof(path));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.headers = headers ?? throw new ArgumentNullException(nameof(headers));
        this.readRow = readRow ?? throw new ArgumentNullException(nameof(readRow));
        this.writeRow = writeRow ?? throw new ArgumentNullException(nameof(writeRow));
    }

    /// <inheritdoc />
    public IEnumerable<T> GetAll()
    {
        foreach (var row in CsvRepositoryHelper.ReadRowsWithRecordNumbers(path, options))
        {
            T item;
            try
            {
                item = readRow(row.Values);
            }
            catch (Exception ex) when (CsvRepositoryHelper.IsReadExceptionCause(ex))
            {
                throw CsvRepositoryHelper.CreateReadException(path, row.RecordNumber, ex);
            }

            yield return item;
        }
    }

    /// <inheritdoc />
    public virtual void EnsureAvailable()
    {
        // 読み取り可否の詳細検証が必要な実装だけ具象クラス側で上書き相当を行います。
    }

    /// <inheritdoc />
    public void Initialize()
    {
        using var writer = CsvRepositoryHelper.CreateWriter(path, options);
        writer.WriteRecord(headers);
    }

    /// <inheritdoc />
    public void AppendRange(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        using var writer = CsvRepositoryHelper.CreateAppendWriter(path, options);
        foreach (var item in items)
        {
            writer.WriteRecord(writeRow(item));
        }
    }

    /// <inheritdoc />
    public void ReplaceAll(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = string.IsNullOrWhiteSpace(directory)
            ? $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp"
            : Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

        try
        {
            using (var writer = CsvRepositoryHelper.CreateWriter(temporaryPath, options))
            {
                writer.WriteRecord(headers);
                foreach (var item in items)
                {
                    writer.WriteRecord(writeRow(item));
                }
            }

            if (File.Exists(path))
            {
                File.Replace(temporaryPath, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, path);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    /// <inheritdoc />
    public void Complete()
    {
    }
}
