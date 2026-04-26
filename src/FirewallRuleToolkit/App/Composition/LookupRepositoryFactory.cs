using FirewallRuleToolkit.Infra;

namespace FirewallRuleToolkit.App.Composition;

/// <summary>
/// lookup repository を一括読み込み済みのメモリ実装として構築します。
/// </summary>
internal static class LookupRepositoryFactory
{
    /// <summary>
    /// 名前付きアドレス定義 lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">名前付きアドレス定義の読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<string> CreateAddressDefinitionLookup(IReadRepository<AddressDefinition> source)
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
    /// 名前付きサービス定義 lookup をメモリ上に構築します。
    /// </summary>
    /// <param name="source">名前付きサービス定義の読み取り元。</param>
    /// <returns>メモリ上の lookup。</returns>
    public static ILookupRepository<ServiceDefinition> CreateServiceDefinitionLookup(IReadRepository<ServiceDefinition> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return new InMemoryLookupRepository<ServiceDefinition>(
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
