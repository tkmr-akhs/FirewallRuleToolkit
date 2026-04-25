using System;
using System.Collections.Generic;
using System.IO;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// テキスト ライターへ CSV レコードを書き出します。
/// </summary>
public sealed class CsvWriter : IDisposable
{
    private readonly TextWriter writer;
    private readonly CsvRecordFormatter formatter;
    private readonly string newLine;
    private bool disposed;

    /// <summary>
    /// テキスト ライターへ CSV レコードを書き出しするクラスのコンストラクターです。
    /// </summary>
    /// <param name="writer">出力先テキスト ライター。</param>
    /// <param name="options">CSV オプション。</param>
    public CsvWriter(TextWriter writer, CsvOptions? options = null)
    {
        this.writer = writer ?? throw new ArgumentNullException(nameof(writer));

        options ??= new CsvOptions();
        formatter = new CsvRecordFormatter(options);
        newLine = ResolveNewLine(options.NewLineMode);
    }

    /// <summary>
    /// 整形済みレコードを書き出します。
    /// </summary>
    /// <param name="record">書き出すレコード文字列。</param>
    public void WriteRecord(string record)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(record);

        writer.Write(record);
        writer.Write(newLine);
    }

    /// <summary>
    /// フィールド一覧を CSV レコードとして書き出します。
    /// </summary>
    /// <param name="fields">書き出すフィールド一覧。</param>
    public void WriteRecord(IList<string> fields)
    {
        ThrowIfDisposed();
        writer.Write(formatter.FormatRecord(fields));
        writer.Write(newLine);
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

        writer.Dispose();
        disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(CsvWriter));
        }
    }

    private static string ResolveNewLine(CsvNewLineMode mode)
    {
        return mode switch
        {
            CsvNewLineMode.Lf => "\n",
            CsvNewLineMode.CrLf => "\r\n",
            CsvNewLineMode.Cr => "\r",
            _ => Environment.NewLine
        };
    }
}
