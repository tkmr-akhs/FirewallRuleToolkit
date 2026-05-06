using System.Text;

namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// CSV の読み書きに使用するオプションを表します。
/// </summary>
public sealed class CsvOptions
{
    /// <summary>
    /// 読み書きに使用する文字エンコーディングを取得します。
    /// </summary>
    public Encoding Encoding { get; init; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    /// <summary>
    /// BOM を付与または許容するかどうかを取得します。
    /// </summary>
    public bool HasByteOrderMarks { get; init; }

    /// <summary>
    /// 改行コードの扱いを取得します。
    /// </summary>
    public CsvNewLineMode NewLineMode { get; init; } = CsvNewLineMode.AutoDetect;

    /// <summary>
    /// 区切り文字を取得します。
    /// </summary>
    public char Delimiter { get; init; } = ',';

    /// <summary>
    /// 引用符文字を取得します。
    /// </summary>
    public char Quote { get; init; } = '"';
}
