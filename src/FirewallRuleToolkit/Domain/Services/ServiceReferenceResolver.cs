namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// サービス参照名を解決し、直接指定値の解釈は <see cref="ServiceValueParser"/> に委譲します。
/// </summary>
public sealed class ServiceReferenceResolver
{
    /// <summary>
    /// サービス オブジェクト参照の lookup です。
    /// </summary>
    private readonly ILookupRepository<ServiceObject> serviceObjectLookup;

    /// <summary>
    /// サービス グループ参照の lookup です。
    /// </summary>
    private readonly ILookupRepository<IReadOnlyList<string>> serviceGroupLookup;

    /// <summary>
    /// サービス参照名を解決するクラスのコンストラクターです。
    /// </summary>
    /// <param name="serviceObjectLookup">サービス オブジェクト lookup。</param>
    /// <param name="serviceGroupLookup">サービス グループ lookup。</param>
    public ServiceReferenceResolver(
        ILookupRepository<ServiceObject> serviceObjectLookup,
        ILookupRepository<IReadOnlyList<string>> serviceGroupLookup)
    {
        this.serviceObjectLookup = serviceObjectLookup ?? throw new ArgumentNullException(nameof(serviceObjectLookup));
        this.serviceGroupLookup = serviceGroupLookup ?? throw new ArgumentNullException(nameof(serviceGroupLookup));
    }

    /// <summary>
    /// 入力値列を解決します。
    /// </summary>
    /// <param name="values">解決対象の値列。</param>
    /// <returns>解決後のサービス オブジェクト列。</returns>
    public IEnumerable<ServiceObject> Resolve(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var visitedGroups = new HashSet<string>(StringComparer.Ordinal);

        foreach (var value in values)
        {
            foreach (var resolved in ResolveValue(value, visitedGroups))
            {
                yield return resolved;
            }
        }
    }

    /// <summary>
    /// 単一の値を解決します。組み込み指定、サービス オブジェクト、サービス グループ、直指定、または Kind 指定として解決を試みます。
    /// </summary>
    /// <param name="value">解決対象のサービス参照。</param>
    /// <param name="visitedGroups">再帰検出済みのサービス グループ名。</param>
    /// <returns>解決後のサービス オブジェクト列。</returns>
    private IEnumerable<ServiceObject> ResolveValue(string value, HashSet<string> visitedGroups)
    {
        if (ServiceValueParser.TryNormalizeBuiltInValue(value, out var builtInValue))
        {
            yield return builtInValue;
            yield break;
        }

        if (serviceObjectLookup.TryGetByName(value, out var serviceObject))
        {
            yield return ServiceValueParser.NormalizeObject(serviceObject);
            yield break;
        }

        if (serviceGroupLookup.TryGetByName(value, out var members))
        {
            if (!visitedGroups.Add(value))
            {
                throw new InvalidOperationException($"Service group recursion detected: {value}");
            }

            try
            {
                foreach (var member in members)
                {
                    foreach (var resolved in ResolveValue(member, visitedGroups))
                    {
                        yield return resolved;
                    }
                }
            }
            finally
            {
                visitedGroups.Remove(value);
            }

            yield break;
        }

        yield return ServiceValueParser.ParseObject(value);
    }
}
