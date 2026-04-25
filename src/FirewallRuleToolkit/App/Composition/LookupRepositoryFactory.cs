using FirewallRuleToolkit.Infra;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// lookup repository を一括読み込み済みのメモリ実装として構築します。
/// </summary>
internal static class LookupRepositoryFactory
{
    /// <summary>
    /// アドレス オブジェクト lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">アドレス オブジェクトの読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<string> CreateAddressObjectLookup(IReadRepository<AddressObject> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return new InMemoryLookupRepository<string>(
            source.GetAll().Select(static item => KeyValuePair.Create(item.Name, item.Value)));
    }

    /// <summary>
    /// アドレス グループ lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">アドレス グループ メンバーの読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<IReadOnlyList<string>> CreateAddressGroupLookup(
        IReadRepository<AddressGroupMembership> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return new InMemoryLookupRepository<IReadOnlyList<string>>(
            source.GetAll()
                .GroupBy(static item => item.GroupName, StringComparer.Ordinal)
                .Select(static group => KeyValuePair.Create(
                    group.Key,
                    (IReadOnlyList<string>)group.Select(static item => item.MemberName).ToArray())));
    }

    /// <summary>
    /// サービス オブジェクト lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">サービス オブジェクトの読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<ServiceObject> CreateServiceObjectLookup(IReadRepository<ServiceObject> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return new InMemoryLookupRepository<ServiceObject>(
            source.GetAll().Select(static item => KeyValuePair.Create(item.Name, item)));
    }

    /// <summary>
    /// サービス グループ lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">サービス グループ メンバーの読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<IReadOnlyList<string>> CreateServiceGroupLookup(
        IReadRepository<ServiceGroupMembership> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return new InMemoryLookupRepository<IReadOnlyList<string>>(
            source.GetAll()
                .GroupBy(static item => item.GroupName, StringComparer.Ordinal)
                .Select(static group => KeyValuePair.Create(
                    group.Key,
                    (IReadOnlyList<string>)group.Select(static item => item.MemberName).ToArray())));
    }
}
