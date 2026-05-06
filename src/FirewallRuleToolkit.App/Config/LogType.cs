namespace FirewallRuleToolkit.Config;

/// <summary>
/// ログ出力先の種別を表します。
/// </summary>
[Flags]
public enum LogType
{
    /// <summary>
    /// コンソール出力のみを行います。
    /// </summary>
    ConsoleOnly = 0x0,

    /// <summary>
    /// ファイル出力を有効にします。
    /// </summary>
    File = 0x1,

    /// <summary>
    /// イベント ログ出力を有効にします。
    /// </summary>
    EventLog = 0x2
}
