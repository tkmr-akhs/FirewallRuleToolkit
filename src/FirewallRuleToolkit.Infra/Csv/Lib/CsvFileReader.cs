using System;
using System.Collections.Generic;
using System.IO;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// ファイルから CSV を読み取ります。
/// </summary>
public sealed class CsvFileReader : IDisposable
{
    private readonly CsvReader csvReader;
    private bool disposed;

    /// <summary>
    /// ファイルから CSV を読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="useFirstRowAsHeader">先頭行をヘッダーとして扱う場合は <see langword="true"/>。</param>
    public CsvFileReader(string path, CsvOptions? options = null, bool useFirstRowAsHeader = false)
    {
        if (path is null)
        {
            throw new ArgumentNullException(nameof(path));
        }

        options ??= new CsvOptions();

        var streamReader = new StreamReader(
            path,
            options.Encoding,
            detectEncodingFromByteOrderMarks: options.HasByteOrderMarks);

        csvReader = new CsvReader(streamReader, options, useFirstRowAsHeader);
    }

    /// <summary>
    /// 1 行を読み取ります。
    /// </summary>
    /// <returns>読み取った行。終端の場合は <see langword="null"/>。</returns>
    public IReadOnlyDictionary<string, string>? ReadRow()
    {
        ThrowIfDisposed();
        return csvReader.ReadRow();
    }

    /// <summary>
    /// 残りの行を順に読み取ります。
    /// </summary>
    /// <returns>行データの列挙。</returns>
    public IEnumerable<IReadOnlyDictionary<string, string>> ReadRows()
    {
        ThrowIfDisposed();
        return csvReader.ReadRows();
    }

    /// <summary>
    /// 使用中のリーダーを破棄します。
    /// </summary>
    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        csvReader.Dispose();
        disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(CsvFileReader));
        }
    }
}
