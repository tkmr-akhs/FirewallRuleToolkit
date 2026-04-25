using System;
using System.Collections.Generic;
using System.IO;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// CSV を行単位で辞書へ変換しながら読み取ります。
/// </summary>
public sealed class CsvReader : IDisposable
{
    private readonly TextReader reader;
    private readonly CsvRecordReader recordReader;
    private readonly CsvRecordParser recordParser;
    private bool disposed;

    /// <summary>
    /// CSV を行単位で辞書へ変換しながら読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="reader">入力元テキスト リーダー。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="useFirstRowAsHeader">先頭行をヘッダーとして扱う場合は <see langword="true"/>。</param>
    public CsvReader(TextReader reader, CsvOptions? options = null, bool useFirstRowAsHeader = false)
    {
        if (reader is null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        options ??= new CsvOptions();

        this.reader = reader;
        recordReader = new CsvRecordReader(reader, options);
        recordParser = new CsvRecordParser(options, ResolveHeaders(recordReader, options, useFirstRowAsHeader));
    }

    /// <summary>
    /// 1 行を読み取り、列名と値の辞書として返します。
    /// </summary>
    /// <returns>読み取った行。終端の場合は <see langword="null"/>。</returns>
    public IReadOnlyDictionary<string, string>? ReadRow()
    {
        ThrowIfDisposed();

        var record = recordReader.ReadRecord();
        if (record is null)
        {
            return null;
        }

        return recordParser.ParseRecord(record);
    }

    /// <summary>
    /// 残りの行を順に読み取ります。
    /// </summary>
    /// <returns>行データの列挙。</returns>
    public IEnumerable<IReadOnlyDictionary<string, string>> ReadRows()
    {
        ThrowIfDisposed();

        while (true)
        {
            var record = recordReader.ReadRecord();
            if (record is null)
            {
                yield break;
            }

            yield return recordParser.ParseRecord(record);
        }
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

        reader.Dispose();
        disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(CsvReader));
        }
    }

    private static IList<string>? ResolveHeaders(
        CsvRecordReader recordReader,
        CsvOptions options,
        bool useFirstRowAsHeader)
    {
        if (!useFirstRowAsHeader)
        {
            return null;
        }

        var headerRecord = recordReader.ReadRecord();
        if (headerRecord is null)
        {
            return [];
        }

        var parsedHeader = CsvRecordParser.Parse(headerRecord, options);
        var resolvedHeaders = new List<string>(parsedHeader.Count);

        for (var i = 0; i < parsedHeader.Count; i++)
        {
            resolvedHeaders.Add(parsedHeader[i.ToString()]);
        }

        return resolvedHeaders;
    }
}
