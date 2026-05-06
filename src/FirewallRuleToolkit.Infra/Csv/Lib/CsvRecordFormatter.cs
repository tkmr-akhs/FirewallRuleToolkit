using System;
using System.Collections.Generic;
using System.Text;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// フィールド一覧を CSV レコード文字列へ整形します。
/// </summary>
public sealed class CsvRecordFormatter
{
    private readonly CsvOptions options;

    /// <summary>
    /// フィールド一覧を CSV レコード文字列へ整形するクラスのコンストラクターです。
    /// </summary>
    /// <param name="options">CSV オプション。</param>
    public CsvRecordFormatter(CsvOptions? options = null)
    {
        this.options = options ?? new CsvOptions();
    }

    /// <summary>
    /// フィールド一覧を CSV レコードへ整形します。
    /// </summary>
    /// <param name="fields">整形するフィールド一覧。</param>
    /// <returns>整形後の CSV レコード。</returns>
    public string FormatRecord(IList<string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        var builder = new StringBuilder();

        for (var i = 0; i < fields.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(options.Delimiter);
            }

            builder.Append(FormatField(fields[i] ?? string.Empty));
        }

        return builder.ToString();
    }

    /// <summary>
    /// フィールド一覧を CSV レコードへ整形します。
    /// </summary>
    /// <param name="fields">整形するフィールド一覧。</param>
    /// <param name="options">CSV オプション。</param>
    /// <returns>整形後の CSV レコード。</returns>
    public static string Format(IList<string> fields, CsvOptions? options = null)
    {
        return new CsvRecordFormatter(options).FormatRecord(fields);
    }

    private string FormatField(string field)
    {
        var escaped = field.Replace(options.Quote.ToString(), new string(options.Quote, 2), StringComparison.Ordinal);
        return $"{options.Quote}{escaped}{options.Quote}";
    }
}
