namespace FirewallRuleToolkit.Infra;

/// <summary>
/// 名前 lookup をメモリ上の辞書で提供します。
/// </summary>
/// <typeparam name="TValue">lookup で取得する値型。</typeparam>
internal sealed class InMemoryLookupRepository<TValue> : ILookupRepository<TValue>
{
    /// <summary>
    /// 名前から値への対応表です。
    /// </summary>
    private readonly IReadOnlyDictionary<string, TValue> values;

    /// <summary>
    /// 名前 lookup をメモリ上の辞書で提供するクラスのコンストラクターです。
    /// </summary>
    /// <param name="values">名前と値の対応。</param>
    public InMemoryLookupRepository(IEnumerable<KeyValuePair<string, TValue>> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        this.values = values.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value,
            StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public void EnsureAvailable()
    {
    }

    /// <inheritdoc />
    public bool TryGetByName(string name, out TValue value)
    {
        ArgumentNullException.ThrowIfNull(name);

        return values.TryGetValue(name, out value!);
    }
}
