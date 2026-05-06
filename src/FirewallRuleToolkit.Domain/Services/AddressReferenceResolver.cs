namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// アドレス参照名を解決し、直接指定値の解釈は <see cref="AddressValueParser"/> に委譲します。
/// </summary>
public sealed class AddressReferenceResolver
{
    /// <summary>
    /// 名前付きアドレス定義の lookup です。
    /// </summary>
    private readonly ILookupRepository<string> addressDefinitionLookup;

    /// <summary>
    /// アドレス グループ参照の lookup です。
    /// </summary>
    private readonly ILookupRepository<IReadOnlyList<string>> addressGroupLookup;

    /// <summary>
    /// アドレス名を解決するクラスのコンストラクターです。
    /// </summary>
    /// <param name="addressDefinitionLookup">名前付きアドレス定義 lookup。</param>
    /// <param name="addressGroupLookup">アドレス グループ lookup。</param>
    public AddressReferenceResolver(
        ILookupRepository<string> addressDefinitionLookup,
        ILookupRepository<IReadOnlyList<string>> addressGroupLookup)
    {
        this.addressDefinitionLookup = addressDefinitionLookup ?? throw new ArgumentNullException(nameof(addressDefinitionLookup));
        this.addressGroupLookup = addressGroupLookup ?? throw new ArgumentNullException(nameof(addressGroupLookup));
    }

    /// <summary>
    /// 入力値列を解決します。
    /// </summary>
    /// <param name="values">解決対象の値列。</param>
    /// <returns>解決後のアドレス値列。</returns>
    public IEnumerable<ResolvedAddress> Resolve(IEnumerable<string> values)
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
    /// 1 つのアドレス参照を解決します。
    /// </summary>
    /// <param name="value">解決対象のアドレス参照。</param>
    /// <param name="visitedGroups">再帰検出済みのアドレス グループ名。</param>
    /// <returns>解決後のアドレス値列。</returns>
    private IEnumerable<ResolvedAddress> ResolveValue(string value, HashSet<string> visitedGroups)
    {
        if (AddressValueParser.TryNormalizeBuiltInValue(value, out var builtInValue))
        {
            yield return CreateResolvedAddress(builtInValue);
            yield break;
        }

        if (addressDefinitionLookup.TryGetByName(value, out var definitionValue))
        {
            yield return CreateResolvedAddress(definitionValue);
            yield break;
        }

        if (addressGroupLookup.TryGetByName(value, out var members))
        {
            if (!visitedGroups.Add(value))
            {
                throw new InvalidOperationException($"Address group recursion detected: {value}");
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

        yield return CreateResolvedAddress(AddressValueParser.NormalizeResolvedValue(value));
    }

    /// <summary>
    /// 解決済みのアドレス値から匿名アドレス値表現を作成します。
    /// </summary>
    /// <param name="value">解決済みのアドレス値。</param>
    /// <returns>匿名アドレス値表現。</returns>
    private static ResolvedAddress CreateResolvedAddress(string value)
    {
        return new ResolvedAddress
        {
            Value = value
        };
    }
}

