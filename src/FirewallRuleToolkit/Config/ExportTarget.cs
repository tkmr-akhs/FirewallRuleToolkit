namespace FirewallRuleToolkit.Config;

/// <summary>
/// export サブコマンドの出力対象を表します。
/// </summary>
[Flags]
public enum ExportTarget
{
    /// <summary>
    /// 出力を行いません。
    /// </summary>
    None = 0x0,

    /// <summary>
    /// 分解済みセキュリティ ポリシー CSV ファイルを出力します。
    /// </summary>
    Atomic = 0x1,

    /// <summary>
    /// 集約済みセキュリティ ポリシー CSV ファイルを出力します。
    /// </summary>
    Merged = 0x2
}
