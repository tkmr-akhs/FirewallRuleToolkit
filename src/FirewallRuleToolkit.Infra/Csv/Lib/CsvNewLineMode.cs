namespace FirewallRuleToolkit.Infra.Csv.Lib;

/// <summary>
/// CSV の改行コードの扱いを表します。
/// </summary>
public enum CsvNewLineMode
{
    /// <summary>
    /// 入力から自動判定します。
    /// </summary>
    AutoDetect,

    /// <summary>
    /// LF を使用します。
    /// </summary>
    Lf,

    /// <summary>
    /// CRLF を使用します。
    /// </summary>
    CrLf,

    /// <summary>
    /// CR を使用します。
    /// </summary>
    Cr
}
