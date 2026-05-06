using System;
using System.Collections.Generic;
using System.Text;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// CSV レコード文字列をフィールド辞書へ変換します。
/// </summary>
public sealed class CsvRecordParser
{
    private readonly CsvOptions options;
    private readonly IList<string>? headers;

    /// <summary>
    /// CSV レコード文字列をフィールド辞書へ変換するクラスのコンストラクターです。
    /// </summary>
    /// <param name="options">CSV オプション。</param>
    /// <param name="headers">ヘッダー一覧。</param>
    public CsvRecordParser(CsvOptions? options = null, IList<string>? headers = null)
    {
        this.options = options ?? new CsvOptions();
        this.headers = headers;
    }

    /// <summary>
    /// 1 件の CSV レコードを辞書へ変換します。
    /// </summary>
    /// <param name="record">変換対象レコード。</param>
    /// <returns>フィールド辞書。</returns>
    public IReadOnlyDictionary<string, string> ParseRecord(string record)
    {
        if (record is null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        var result = new List<string>();
        var field = new StringBuilder();

        var inQuotes = false;
        var fieldStarted = false;
        var quotedFieldClosed = false;

        for (var i = 0; i < record.Length; i++)
        {
            var c = record[i];

            if (inQuotes)
            {
                if (c == options.Quote)
                {
                    if (i + 1 < record.Length && record[i + 1] == options.Quote)
                    {
                        field.Append(options.Quote);
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                        quotedFieldClosed = true;
                    }
                }
                else
                {
                    field.Append(c);
                }

                continue;
            }

            if (!fieldStarted)
            {
                fieldStarted = true;

                if (c == options.Delimiter)
                {
                    result.Add(string.Empty);
                    fieldStarted = false;
                    continue;
                }

                if (c == options.Quote)
                {
                    inQuotes = true;
                    continue;
                }

                field.Append(c);
                continue;
            }

            if (c == options.Delimiter)
            {
                result.Add(field.ToString());
                field.Clear();
                fieldStarted = false;
                quotedFieldClosed = false;
                continue;
            }

            if (quotedFieldClosed)
            {
                throw new FormatException($"CSV field format is invalid. index={i}");
            }

            if (c == options.Quote)
            {
                throw new FormatException($"CSV field format is invalid. index={i}");
            }

            field.Append(c);
        }

        if (inQuotes)
        {
            throw new FormatException("CSV record contains an unclosed quoted field.");
        }

        if (!fieldStarted)
        {
            result.Add(string.Empty);
        }
        else
        {
            result.Add(field.ToString());
        }

        return CreateRecordMap(result);
    }

    /// <summary>
    /// 1 件の CSV レコードを辞書へ変換します。
    /// </summary>
    /// <param name="record">変換対象レコード。</param>
    /// <param name="options">CSV オプション。</param>
    /// <param name="headers">ヘッダー一覧。</param>
    /// <returns>フィールド辞書。</returns>
    public static IReadOnlyDictionary<string, string> Parse(
        string record,
        CsvOptions? options = null,
        IList<string>? headers = null)
    {
        return new CsvRecordParser(options, headers).ParseRecord(record);
    }

    private IReadOnlyDictionary<string, string> CreateRecordMap(IReadOnlyList<string> fields)
    {
        var map = new Dictionary<string, string>(fields.Count);

        if (headers is null)
        {
            for (var i = 0; i < fields.Count; i++)
            {
                map[i.ToString()] = fields[i];
            }

            return map;
        }

        if (headers.Count != fields.Count)
        {
            throw new FormatException("CSV header count does not match field count.");
        }

        for (var i = 0; i < headers.Count; i++)
        {
            map[headers[i]] = fields[i];
        }

        return map;
    }
}
