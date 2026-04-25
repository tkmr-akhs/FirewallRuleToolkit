using System;
using System.Collections.Generic;
using System.IO;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// ファイルへ CSV を書き出します。
/// </summary>
public sealed class CsvFileWriter : IDisposable
{
    private readonly CsvWriter csvWriter;
    private bool disposed;

    /// <summary>
    /// ファイルへ CSV を書き出しするクラスのコンストラクターです。
    /// </summary>
    /// <param name="path">出力先 CSV ファイル パス。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="append">既存ファイルへ追記する場合は true。</param>
    public CsvFileWriter(string path, CsvOptions? options = null, bool append = false)
    {
        if (path is null)
        {
            throw new ArgumentNullException(nameof(path));
        }

        options ??= new CsvOptions();

        var streamWriter = new StreamWriter(
            path,
            append: append,
            encoding: options.Encoding);

        csvWriter = new CsvWriter(streamWriter, options);
    }

    /// <summary>
    /// 整形済みレコードを書き出します。
    /// </summary>
    /// <param name="record">書き出すレコード文字列。</param>
    public void WriteRecord(string record)
    {
        ThrowIfDisposed();
        csvWriter.WriteRecord(record);
    }

    /// <summary>
    /// フィールド一覧を CSV レコードとして書き出します。
    /// </summary>
    /// <param name="fields">書き出すフィールド一覧。</param>
    public void WriteRecord(IList<string> fields)
    {
        ThrowIfDisposed();
        csvWriter.WriteRecord(fields);
    }

    /// <summary>
    /// 使用中のライターを破棄します。
    /// </summary>
    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        csvWriter.Dispose();
        disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(CsvFileWriter));
        }
    }
}
