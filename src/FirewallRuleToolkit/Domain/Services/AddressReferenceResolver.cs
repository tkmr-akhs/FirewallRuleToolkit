namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// アドレス参照名を解決し、直接指定値の解釈は <see cref="AddressValueParser"/> に委譲します。
/// </summary>
public sealed class AddressReferenceResolver
{
    /// <summary>
    /// アドレス オブジェクト参照の lookup です。
    /// </summary>
    private readonly ILookupRepository<string> addressObjectLookup;

    /// <summary>
    /// アドレス グループ参照の lookup です。
    /// </summary>
    private readonly ILookupRepository<IReadOnlyList<string>> addressGroupLookup;

    /// <summary>
    /// アドレス名を解決するクラスのコンストラクターです。
    /// </summary>
    /// <param name="addressObjectLookup">アドレス オブジェクト lookup。</param>
    /// <param name="addressGroupLookup">アドレス グループ lookup。</param>
    public AddressReferenceResolver(
        ILookupRepository<string> addressObjectLookup,
        ILookupRepository<IReadOnlyList<string>> addressGroupLookup)
    {
        this.addressObjectLookup = addressObjectLookup ?? throw new ArgumentNullException(nameof(addressObjectLookup));
        this.addressGroupLookup = addressGroupLookup ?? throw new ArgumentNullException(nameof(addressGroupLookup));
    }

    /// <summary>
    /// 入力値列を解決します。
    /// </summary>
    /// <param name="values">解決対象の値列。</param>
    /// <returns>解決後のアドレス オブジェクト列。</returns>
    public IEnumerable<AddressObject> Resolve(IEnumerable<string> values)
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
    /// <returns>解決後のアドレス オブジェクト列。</returns>
    private IEnumerable<AddressObject> ResolveValue(string value, HashSet<string> visitedGroups)
    {
        if (AddressValueParser.TryNormalizeBuiltInValue(value, out var builtInValue))
        {
            yield return CreateResolvedAddressObject(builtInValue);
            yield break;
        }

        if (addressObjectLookup.TryGetByName(value, out var objectValue))
        {
            yield return CreateResolvedAddressObject(objectValue);
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

        yield return CreateResolvedAddressObject(AddressValueParser.NormalizeObjectValue(value));
    }

    /// <summary>
    /// 解決済みのアドレス値から匿名アドレス オブジェクトを作成します。
    /// </summary>
    /// <param name="value">解決済みのアドレス値。</param>
    /// <returns>匿名アドレス オブジェクト。</returns>
    private static AddressObject CreateResolvedAddressObject(string value)
    {
        return new AddressObject
        {
            Name = string.Empty,
            Value = value
        };
    }
}

