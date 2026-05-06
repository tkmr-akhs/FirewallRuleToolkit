namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// セキュリティ ポリシーを原子的な単位へ分解します。
/// </summary>
internal sealed class SecurityPolicyAtomizer
{
    /// <summary>
    /// 範囲を単一値へ分解するかどうかを決めるしきい値です。
    /// </summary>
    private readonly int threshold;

    /// <summary>
    /// デバッグ ログ出力先です。(現状では使用しませんが、将来的に分解の過程でログを出力する可能性があります)
    /// </summary>
    private readonly ILogger logger;

    /// <summary>
    /// セキュリティ ポリシーを原子的な単位へ分解するクラスのコンストラクターです。
    /// </summary>
    /// <param name="threshold">範囲を単一値へ分解するしきい値。</param>
    /// <param name="logger">デバッグ ログ出力先。</param>
    public SecurityPolicyAtomizer(int threshold, ILogger? logger = null)
    {
        if (threshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "Threshold must be greater than zero.");
        }

        this.threshold = threshold;
        this.logger = logger.OrNullLogger();
    }

    /// <summary>
    /// セキュリティ ポリシー 1 件を原子的な単位へ分解します。
    /// </summary>
    /// <param name="policy">分解対象のセキュリティ ポリシー。</param>
    /// <returns>分解後の原子的なポリシー列。</returns>
    public IEnumerable<AtomicSecurityPolicy> Atomize(ResolvedSecurityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        // 送信元アドレス範囲の配列
        var sourceAddressRanges = ResolvedAddressExpander
            .Expand(policy.SourceAddresses, threshold)
            .ToArray();

        // 宛先アドレスの配列
        var destinationAddressRanges = ResolvedAddressExpander
            .Expand(policy.DestinationAddresses, threshold)
            .ToArray();

        // サービスの配列
        var serviceRanges = ResolvedServiceExpander
            .Expand(policy.Services, threshold)
            .ToArray();

        // ポリシーから取り出した着信ゾーン
        foreach (var fromZone in policy.FromZones)
        {
            // ポリシーから取り出した送信元アドレス
            foreach (var sourceAddressRange in sourceAddressRanges)
            {
                // ポリシーから取り出した発信ゾーン
                foreach (var toZone in policy.ToZones)
                {
                    // ポリシーから取り出した宛先アドレス
                    foreach (var destinationAddressRange in destinationAddressRanges)
                    {
                        // ポリシーから取り出したアプリケーション
                        foreach (var application in policy.Applications)
                        {
                            // ポリシーから取り出したサービス
                            foreach (var serviceRange in serviceRanges)
                            {
                                yield return new AtomicSecurityPolicy
                                {
                                    FromZone = fromZone,
                                    SourceAddress = sourceAddressRange,
                                    ToZone = toZone,
                                    DestinationAddress = destinationAddressRange,
                                    Application = application,
                                    Service = serviceRange,
                                    Action = policy.Action,
                                    GroupId = policy.GroupId,
                                    OriginalIndex = policy.Index,
                                    OriginalPolicyName = policy.Name
                                };
                            }
                        }
                    }
                }
            }
        }
    }
}
