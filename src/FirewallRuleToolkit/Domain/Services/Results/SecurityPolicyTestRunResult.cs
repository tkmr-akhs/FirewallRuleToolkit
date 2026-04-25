namespace FirewallRuleToolkit.Domain.Services.Results;

/// <summary>
/// test 検査実行の結果要約です。
/// </summary>
internal sealed class SecurityPolicyTestRunResult
{
    /// <summary>
    /// 検査対象として処理した Atomic ポリシー件数を取得します。
    /// </summary>
    public long ProcessedAtomicCount { get; init; }

    /// <summary>
    /// shadowed ではない Atomic ポリシー件数を取得します。
    /// </summary>
    public long NonShadowedAtomicCount { get; init; }

    /// <summary>
    /// shadowed になった Atomic ポリシー件数を取得します。
    /// </summary>
    public long ShadowedAtomicCount { get; init; }

    /// <summary>
    /// warning として記録した件数を取得します。
    /// </summary>
    public long WarningCount { get; init; }

    /// <summary>
    /// informational として記録した件数を取得します。
    /// </summary>
    public long InformationalCount { get; init; }
}
