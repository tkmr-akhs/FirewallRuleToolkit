namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// 未解決セキュリティ ポリシー内の参照名を解決します。
/// </summary>
internal sealed class SecurityPolicyResolver
{
    private readonly AddressReferenceResolver addressResolver;
    private readonly ServiceReferenceResolver serviceResolver;

    /// <summary>
    /// 未解決セキュリティ ポリシー内の参照名を解決するクラスのコンストラクターです。
    /// </summary>
    public SecurityPolicyResolver(
        AddressReferenceResolver addressResolver,
        ServiceReferenceResolver serviceResolver)
    {
        this.addressResolver = addressResolver ?? throw new ArgumentNullException(nameof(addressResolver));
        this.serviceResolver = serviceResolver ?? throw new ArgumentNullException(nameof(serviceResolver));
    }

    /// <summary>
    /// 未解決セキュリティ ポリシー 1 件を解決済みへ変換します。
    /// </summary>
    public ResolvedSecurityPolicy Resolve(ImportedSecurityPolicy sourcePolicy)
    {
        ArgumentNullException.ThrowIfNull(sourcePolicy);

        return new ResolvedSecurityPolicy
        {
            Index = sourcePolicy.Index,
            Name = sourcePolicy.Name,
            FromZones = sourcePolicy.FromZones,
            SourceAddresses = addressResolver.Resolve(sourcePolicy.SourceAddressReferences).ToArray(),
            ToZones = sourcePolicy.ToZones,
            DestinationAddresses = addressResolver.Resolve(sourcePolicy.DestinationAddressReferences).ToArray(),
            Applications = sourcePolicy.Applications,
            Services = serviceResolver.Resolve(sourcePolicy.ServiceReferences).ToArray(),
            Action = sourcePolicy.Action,
            GroupId = sourcePolicy.GroupId
        };
    }

    /// <summary>
    /// 未解決セキュリティ ポリシー列を順に解決します。
    /// </summary>
    public IEnumerable<ResolvedSecurityPolicy> Resolve(IEnumerable<ImportedSecurityPolicy> sourcePolicies)
    {
        ArgumentNullException.ThrowIfNull(sourcePolicies);

        foreach (var sourcePolicy in sourcePolicies)
        {
            yield return Resolve(sourcePolicy);
        }
    }
}
