namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// サービス グループとそのメンバーの所属関係を保持します。
/// </summary>
public sealed class ServiceGroupMembership
{
    /// <summary>
    /// グループ名を取得します。
    /// </summary>
    public required string GroupName { get; init; }

    /// <summary>
    /// メンバー名を取得します。
    /// </summary>
    public required string MemberName { get; init; }
}
