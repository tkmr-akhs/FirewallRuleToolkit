namespace FirewallRuleToolkit.Domain.Enums;

/// <summary>
/// セキュリティ ポリシーのアクション種別を表します。
/// </summary>
public enum SecurityPolicyAction
{
    /// <summary>
    /// 許可を表します。
    /// </summary>
    Allow = 1,

    /// <summary>
    /// 拒否を表します。
    /// </summary>
    Deny = 2,

    /// <summary>
    /// ドロップを表します。
    /// </summary>
    Drop = 3,

    /// <summary>
    /// 双方向リセットを表します。
    /// </summary>
    ResetBoth = 4
}
