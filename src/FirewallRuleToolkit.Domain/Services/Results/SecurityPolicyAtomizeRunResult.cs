namespace FirewallRuleToolkit.Domain.Services.Results;

/// <summary>
/// atomic 構築実行の結果要約です。
/// </summary>
public sealed class SecurityPolicyAtomizeRunResult
{
    /// <summary>
    /// 処理した入力ポリシー件数を取得します。
    /// </summary>
    public int ProcessedSourcePolicyCount { get; init; }

    /// <summary>
    /// アドレス条件を atomic 化できずにスキップした入力ポリシー件数を取得します。
    /// </summary>
    public int SkippedSourcePolicyCount { get; init; }
}
