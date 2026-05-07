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
        var sourceAddressRanges = ExpandAddresses(policy.SourceAddresses, "source");

        // 宛先アドレスの配列
        var destinationAddressRanges = ExpandAddresses(policy.DestinationAddresses, "destination");

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

    /// <summary>
    /// 解決済みアドレス列を atomize 用のアドレス範囲配列へ変換します。
    /// </summary>
    /// <param name="addresses">変換対象の解決済みアドレス列。</param>
    /// <param name="addressKind">送信元または宛先を表す名前。</param>
    /// <returns>変換したアドレス範囲配列。</returns>
    private AddressValue[] ExpandAddresses(IEnumerable<ResolvedAddress> addresses, string addressKind)
    {
        try
        {
            return ResolvedAddressExpander
                .Expand(addresses, threshold)
                .ToArray();
        }
        catch (FormatException exception)
        {
            throw new UnsupportedAddressPolicyException(addressKind, exception);
        }
    }
}

/// <summary>
/// アドレス条件を atomic 化可能な IPv4 範囲として解釈できなかったことを表します。
/// </summary>
internal sealed class UnsupportedAddressPolicyException : Exception
{
    /// <summary>
    /// アドレス条件を atomic 化可能な IPv4 範囲として解釈できなかったことを表す例外を初期化します。
    /// </summary>
    /// <param name="addressKind">送信元または宛先を表す名前。</param>
    /// <param name="innerException">実際のアドレス解釈エラー。</param>
    public UnsupportedAddressPolicyException(string addressKind, Exception innerException)
        : base($"Unsupported {addressKind} address value.", innerException)
    {
        AddressKind = addressKind;
    }

    /// <summary>
    /// 送信元または宛先を表す名前を取得します。
    /// </summary>
    public string AddressKind { get; }
}
