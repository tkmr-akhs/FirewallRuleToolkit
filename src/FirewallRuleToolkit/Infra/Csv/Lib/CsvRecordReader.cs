using System;
using System.IO;
using System.Text;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// テキストから CSV レコードを 1 件ずつ読み取ります。
/// </summary>
public sealed class CsvRecordReader
{
    private readonly TextReader reader;
    private readonly CsvOptions options;
    private CsvNewLineMode? detectedNewLineMode;

    /// <summary>
    /// テキストから CSV レコードを 1 件ずつ読み取りするクラスのコンストラクターです。
    /// </summary>
    /// <param name="reader">入力元テキスト リーダー。</param>
    /// <param name="options">CSV オプション。</param>
    public CsvRecordReader(TextReader reader, CsvOptions? options = null)
    {
        this.reader = reader ?? throw new ArgumentNullException(nameof(reader));
        this.options = options ?? new CsvOptions();
    }

    /// <summary>
    /// 次の CSV レコードを読み取ります。
    /// </summary>
    /// <returns>読み取ったレコード。終端の場合は <see langword="null"/>。</returns>
    public string? ReadRecord()
    {
        var record = new StringBuilder();
        var inQuotes = false;
        var anyCharRead = false;

        while (true)
        {
            var current = reader.Read();
            if (current < 0)
            {
                if (!anyCharRead)
                {
                    return null;
                }

                if (inQuotes)
                {
                    throw new FormatException("CSV record ended before a quoted field was closed.");
                }

                return record.ToString();
            }

            anyCharRead = true;
            var c = (char)current;

            if (c == options.Quote)
            {
                if (inQuotes)
                {
                    var peek = reader.Peek();
                    if (peek == options.Quote)
                    {
                        record.Append(c);
                        record.Append((char)reader.Read());
                    }
                    else
                    {
                        inQuotes = false;
                        record.Append(c);
                    }
                }
                else
                {
                    inQuotes = true;
                    record.Append(c);
                }

                continue;
            }

            if (!inQuotes && TryConsumeRecordTerminator(c, out var isRecordEnd))
            {
                if (isRecordEnd)
                {
                    return record.ToString();
                }

                continue;
            }

            record.Append(c);
        }
    }

    private bool TryConsumeRecordTerminator(char c, out bool isRecordEnd)
    {
        isRecordEnd = false;

        var activeMode = options.NewLineMode == CsvNewLineMode.AutoDetect
            ? detectedNewLineMode ?? CsvNewLineMode.AutoDetect
            : options.NewLineMode;

        if (activeMode == CsvNewLineMode.AutoDetect)
        {
            if (c == '\n')
            {
                detectedNewLineMode = CsvNewLineMode.Lf;
                isRecordEnd = true;
                return true;
            }

            if (c == '\r')
            {
                var peek = reader.Peek();
                if (peek == '\n')
                {
                    reader.Read();
                    detectedNewLineMode = CsvNewLineMode.CrLf;
                }
                else
                {
                    detectedNewLineMode = CsvNewLineMode.Cr;
                }

                isRecordEnd = true;
                return true;
            }

            return false;
        }

        switch (activeMode)
        {
            case CsvNewLineMode.Lf:
                if (c == '\n')
                {
                    isRecordEnd = true;
                    return true;
                }

                return false;
            case CsvNewLineMode.Cr:
                if (c == '\r')
                {
                    isRecordEnd = true;
                    return true;
                }

                return false;
            case CsvNewLineMode.CrLf:
                if (c == '\r' && reader.Peek() == '\n')
                {
                    reader.Read();
                    isRecordEnd = true;
                    return true;
                }

                return false;
            default:
                return false;
        }
    }
}
