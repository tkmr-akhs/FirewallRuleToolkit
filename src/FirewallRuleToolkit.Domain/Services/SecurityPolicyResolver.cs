namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// 未解決セキュリティ ポリシー内の参照名を解決します。
/// </summary>
public sealed class SecurityPolicyResolver
{
    /// <summary>
    /// アドレス参照を解決する resolver です。
    /// </summary>
    private readonly AddressReferenceResolver addressResolver;

    /// <summary>
    /// サービス参照を解決する resolver です。
    /// </summary>
    private readonly ServiceReferenceResolver serviceResolver;

    /// <summary>
    /// 未解決セキュリティ ポリシー内の参照名を解決するクラスのコンストラクターです。
    /// </summary>
    /// <param name="addressResolver">アドレス参照 resolver。</param>
    /// <param name="serviceResolver">サービス参照 resolver。</param>
    public SecurityPolicyResolver(
        AddressReferenceResolver addressResolver,
        ServiceReferenceResolver serviceResolver)
    {
        this.addressResolver = addressResolver ?? throw new ArgumentNullException(nameof(addressResolver));
        this.serviceResolver = serviceResolver ?? throw new ArgumentNullException(nameof(serviceResolver));
    }

    /// <summary>
    /// サービス参照が canonical direct service として解釈できず、Kind 指定へフォールバックしたときに発生します。
    /// </summary>
    public event Action<string?, uint?, string>? ServiceReferenceKindFallbackOccurred;

    /// <summary>
    /// 未解決セキュリティ ポリシー 1 件を解決済みへ変換します。
    /// </summary>
    /// <param name="sourcePolicy">解決対象の未解決セキュリティ ポリシー。</param>
    /// <returns>解決済みセキュリティ ポリシー。</returns>
    public ResolvedSecurityPolicy Resolve(ImportedSecurityPolicy sourcePolicy)
    {
        ArgumentNullException.ThrowIfNull(sourcePolicy);

        var resolvedSourceAddresses = addressResolver.Resolve(sourcePolicy.SourceAddressReferences).ToArray();
        var resolvedDestinationAddresses = addressResolver.Resolve(sourcePolicy.DestinationAddressReferences).ToArray();
        var resolvedServices = ResolveServices(sourcePolicy);

        return new ResolvedSecurityPolicy
        {
            Index = sourcePolicy.Index,
            Name = sourcePolicy.Name,
            FromZones = sourcePolicy.FromZones,
            SourceAddresses = resolvedSourceAddresses,
            ToZones = sourcePolicy.ToZones,
            DestinationAddresses = resolvedDestinationAddresses,
            Applications = sourcePolicy.Applications,
            Services = resolvedServices,
            Action = sourcePolicy.Action,
            GroupId = sourcePolicy.GroupId
        };
    }

    /// <summary>
    /// 未解決セキュリティ ポリシー列を順に解決します。
    /// </summary>
    /// <param name="sourcePolicies">解決対象の未解決セキュリティ ポリシー列。</param>
    /// <returns>解決済みセキュリティ ポリシー列。</returns>
    public IEnumerable<ResolvedSecurityPolicy> Resolve(IEnumerable<ImportedSecurityPolicy> sourcePolicies)
    {
        ArgumentNullException.ThrowIfNull(sourcePolicies);

        foreach (var sourcePolicy in sourcePolicies)
        {
            yield return Resolve(sourcePolicy);
        }
    }

    /// <summary>
    /// サービス参照を解決し、解決中に発生した Kind フォールバック通知へポリシー文脈を補完します。
    /// </summary>
    /// <param name="sourcePolicy">解決対象の未解決セキュリティ ポリシー。</param>
    /// <returns>解決後のサービス定義配列。</returns>
    private ResolvedService[] ResolveServices(ImportedSecurityPolicy sourcePolicy)
    {
        void ReportKindFallback(string serviceReference)
        {
            ServiceReferenceKindFallbackOccurred?.Invoke(sourcePolicy.Name, sourcePolicy.Index, serviceReference);
        }

        serviceResolver.KindFallbackOccurred += ReportKindFallback;
        try
        {
            return serviceResolver.Resolve(sourcePolicy.ServiceReferences).ToArray();
        }
        finally
        {
            serviceResolver.KindFallbackOccurred -= ReportKindFallback;
        }
    }
}
