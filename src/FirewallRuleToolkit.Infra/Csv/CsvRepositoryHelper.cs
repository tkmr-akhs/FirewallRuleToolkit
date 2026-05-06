using FirewallRuleToolkit.Infra.Csv.Lib;

namespace FirewallRuleToolkit.Infra.Csv;

/// <summary>
/// CSV ストア実装の共通処理を提供します。
/// </summary>
internal static class CsvRepositoryHelper
{
    /// <summary>
    /// ヘッダー付き CSV の行を列挙します。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <returns>行データの列挙。</returns>
    public static IEnumerable<IReadOnlyDictionary<string, string>> ReadRows(string path, CsvOptions options)
    {
        foreach (var row in ReadRowsWithRecordNumbers(path, options))
        {
            yield return row.Values;
        }
    }

    /// <summary>
    /// ヘッダー付き CSV の行をレコード番号付きで列挙します。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <returns>レコード番号と行データの列挙。</returns>
    public static IEnumerable<(int RecordNumber, IReadOnlyDictionary<string, string> Values)> ReadRowsWithRecordNumbers(
        string path,
        CsvOptions options)
    {
        using var reader = CreateReader(path, options);
        using var rows = reader.ReadRows().GetEnumerator();
        var lastRecordNumber = 1;

        while (true)
        {
            var currentRecordNumber = lastRecordNumber + 1;
            IReadOnlyDictionary<string, string>? row;
            bool hasRow;
            try
            {
                hasRow = rows.MoveNext();
                row = hasRow ? rows.Current : null;
            }
            catch (FormatException ex)
            {
                throw CreateReadException(path, currentRecordNumber, ex);
            }

            if (!hasRow)
            {
                yield break;
            }

            lastRecordNumber = currentRecordNumber;
            yield return (currentRecordNumber, row!);
        }
    }

    /// <summary>
    /// 出力先ディレクトリを整えたうえで CSV ライターを生成します。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <returns>生成された CSV ライター。</returns>
    public static CsvFileWriter CreateWriter(string path, CsvOptions options)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return new CsvFileWriter(path, options);
    }

    /// <summary>
    /// 出力先ディレクトリを整えたうえで追記用 CSV ライターを生成します。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <returns>生成された CSV ライター。</returns>
    public static CsvFileWriter CreateAppendWriter(string path, CsvOptions options)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return new CsvFileWriter(path, options, append: true);
    }

    /// <summary>
    /// 必須列の値を取得します。
    /// </summary>
    /// <param name="row">対象行。</param>
    /// <param name="headerName">ヘッダー名。</param>
    /// <returns>取得した値。</returns>
    public static string GetRequiredValue(IReadOnlyDictionary<string, string> row, string headerName)
    {
        if (row.TryGetValue(headerName, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        throw new FormatException($"CSV column '{headerName}' is missing or empty.");
    }

    /// <summary>
    /// CSV 読み取り時の形式エラーまたは値変換エラーを repository 読み取り例外へ変換します。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="recordNumber">CSV の論理レコード番号。ヘッダーを 1 として数えます。</param>
    /// <param name="exception">変換元の原因例外。</param>
    /// <returns>repository 読み取り例外。</returns>
    public static RepositoryReadException CreateReadException(
        string path,
        int recordNumber,
        Exception exception)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(recordNumber);
        ArgumentNullException.ThrowIfNull(exception);

        return new RepositoryReadException(
            $"CSV read failed. path: \"{path}\", record: {recordNumber}, reason: {exception.Message}",
            exception);
    }

    /// <summary>
    /// CSV 行からドメイン値への変換中に発生した読み取り失敗として扱う例外かを判定します。
    /// </summary>
    /// <param name="exception">判定対象の例外。</param>
    /// <returns>読み取り失敗として扱う場合は <see langword="true"/>。</returns>
    public static bool IsReadExceptionCause(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception is FormatException
            or OverflowException
            or ArgumentException
            or System.Text.Json.JsonException;
    }

    private static CsvFileReader CreateReader(string path, CsvOptions options)
    {
        try
        {
            return new CsvFileReader(path, options, useFirstRowAsHeader: true);
        }
        catch (FormatException ex)
        {
            throw CreateReadException(path, 1, ex);
        }
    }
}
