namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// アドレス グループとそのメンバーの所属関係を保持します。
/// </summary>
public sealed class AddressGroupMembership
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
