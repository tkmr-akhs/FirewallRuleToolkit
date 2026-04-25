using System.Collections.Frozen;

namespace FirewallRuleToolkit.Domain.Entities;

/// <summary>
/// セキュリティ ポリシー 1 件分の情報を保持します。
/// </summary>
public sealed class MergedSecurityPolicy
{
    /// <summary>
    /// 送信元ゾーン一覧です。
    /// </summary>
    private IReadOnlyCollection<string> fromZones = CreateFrozenStringSet(Array.Empty<string>());

    /// <summary>
    /// 送信元アドレス一覧です。
    /// </summary>
    private IReadOnlyCollection<AddressValue> sourceAddresses = CreateFrozenSet(Array.Empty<AddressValue>());

    /// <summary>
    /// 宛先ゾーン一覧です。
    /// </summary>
    private IReadOnlyCollection<string> toZones = CreateFrozenStringSet(Array.Empty<string>());

    /// <summary>
    /// 宛先アドレス一覧です。
    /// </summary>
    private IReadOnlyCollection<AddressValue> destinationAddresses = CreateFrozenSet(Array.Empty<AddressValue>());

    /// <summary>
    /// アプリケーション一覧です。
    /// </summary>
    private IReadOnlyCollection<string> applications = CreateFrozenStringSet(Array.Empty<string>());

    /// <summary>
    /// サービス定義一覧です。
    /// </summary>
    private IReadOnlyCollection<ServiceValue> services = CreateFrozenSet(Array.Empty<ServiceValue>());

    /// <summary>
    /// 元ポリシー名集合です。
    /// </summary>
    private IReadOnlyCollection<string> originalPolicyNames = CreateFrozenStringSet(Array.Empty<string>());

    /// <summary>
    /// 送信元ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<string> FromZones
    {
        get => fromZones;
        init => fromZones = CreateFrozenStringSet(value);
    }

    /// <summary>
    /// 送信元アドレス一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<AddressValue> SourceAddresses
    {
        get => sourceAddresses;
        init => sourceAddresses = CreateFrozenSet(value);
    }

    /// <summary>
    /// 宛先ゾーン一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<string> ToZones
    {
        get => toZones;
        init => toZones = CreateFrozenStringSet(value);
    }

    /// <summary>
    /// 宛先アドレス一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<AddressValue> DestinationAddresses
    {
        get => destinationAddresses;
        init => destinationAddresses = CreateFrozenSet(value);
    }

    /// <summary>
    /// アプリケーション一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<string> Applications
    {
        get => applications;
        init => applications = CreateFrozenStringSet(value);
    }

    /// <summary>
    /// サービス定義一覧を取得します。
    /// </summary>
    public required IReadOnlyCollection<ServiceValue> Services
    {
        get => services;
        init => services = CreateFrozenSet(value);
    }

    /// <summary>
    /// アクションを取得します。
    /// </summary>
    public SecurityPolicyAction Action { get; init; }

    /// <summary>
    /// グループ識別子を取得します。
    /// </summary>
    public required string GroupId { get; init; }

    /// <summary>
    /// 最小インデックスを取得します。
    /// </summary>
    public ulong MinimumIndex { get; init; }

    /// <summary>
    /// 最大インデックスを取得します。
    /// </summary>
    public ulong MaximumIndex { get; init; }

    /// <summary>
    /// 元ポリシー名集合を取得します。
    /// </summary>
    public IReadOnlyCollection<string> OriginalPolicyNames
    {
        get => originalPolicyNames;
        init => originalPolicyNames = CreateFrozenStringSet(value);
    }

    /// <summary>
    /// 文字列集合を変更不能な集合として保持します。
    /// </summary>
    /// <param name="values">元になる値の列挙。</param>
    /// <returns>変更不能な文字列集合。</returns>
    private static IReadOnlyCollection<string> CreateFrozenStringSet(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values.ToFrozenSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// 値集合を変更不能な集合として保持します。
    /// </summary>
    /// <typeparam name="T">集合要素型。</typeparam>
    /// <param name="values">元になる値の列挙。</param>
    /// <returns>変更不能な値集合。</returns>
    private static IReadOnlyCollection<T> CreateFrozenSet<T>(IEnumerable<T> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return values.ToFrozenSet();
    }
}
