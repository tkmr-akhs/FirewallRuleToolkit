namespace FirewallRuleToolkit.Domain.Services;

/// <summary>
/// 解決済みアドレス値を数値範囲へ正規化し、必要に応じて単一値へ展開します。
/// </summary>
internal static class ResolvedAddressExpander
{
    /// <summary>
    /// 解決済みアドレス値群を、必要に応じて単一値まで展開した範囲列へ変換します。
    /// </summary>
    /// <param name="addresses">変換対象の解決済みアドレス値列。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後のアドレス範囲列。</returns>
    public static IEnumerable<AddressValue> Expand(IEnumerable<ResolvedAddress> addresses, int threshold)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        ValidateThreshold(threshold);

        foreach (var address in addresses)
        {
            foreach (var expanded in Expand(address, threshold))
            {
                yield return expanded;
            }
        }
    }

    /// <summary>
    /// 解決済みアドレス値 1 件を範囲値へ変換します。
    /// </summary>
    /// <param name="address">変換対象の解決済みアドレス値。</param>
    /// <returns>変換したアドレス範囲。</returns>
    public static AddressValue Parse(ResolvedAddress address)
    {
        return AddressValueParser.Parse(ResolveAddressValue(address));
    }

    /// <summary>
    /// 解決済みアドレス値 1 件を、必要に応じて単一値まで展開した範囲列へ変換します。
    /// </summary>
    /// <param name="address">変換対象の解決済みアドレス値。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後のアドレス範囲列。</returns>
    public static IEnumerable<AddressValue> Expand(ResolvedAddress address, int threshold)
    {
        ValidateThreshold(threshold);

        var rawValue = ResolveAddressValue(address);
        var parsedAddress = AddressValueParser.Parse(rawValue);
        if (!ShouldSplitRange(rawValue))
        {
            yield return parsedAddress;
            yield break;
        }

        foreach (var expanded in ExpandRange(parsedAddress, threshold))
        {
            yield return expanded;
        }
    }

    /// <summary>
    /// 範囲値を必要に応じて単一値へ展開します。
    /// </summary>
    /// <param name="range">展開対象の範囲。</param>
    /// <param name="threshold">範囲を分解するしきい値。</param>
    /// <returns>展開後の範囲列。</returns>
    private static IEnumerable<AddressValue> ExpandRange(AddressValue range, int threshold)
    {
        var count = (ulong)range.Finish - range.Start + 1UL;
        if (count >= (ulong)threshold)
        {
            yield return range;
            yield break;
        }

        for (var value = range.Start; ; value++)
        {
            yield return new AddressValue
            {
                Start = value,
                Finish = value
            };

            if (value == range.Finish)
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// 生アドレス値を単一値まで分解すべきかを判定します。
    /// </summary>
    /// <param name="value">判定対象のアドレス値。</param>
    /// <returns>ハイフン範囲のとき <see langword="true"/>。</returns>
    private static bool ShouldSplitRange(string value)
    {
        return value.Contains('-', StringComparison.Ordinal);
    }

    /// <summary>
    /// 解決済みアドレス値から実際のアドレス値文字列を取り出します。
    /// </summary>
    /// <param name="address">対象の解決済みアドレス値。</param>
    /// <returns>正規化前のアドレス値。</returns>
    private static string ResolveAddressValue(ResolvedAddress address)
    {
        var value = address.Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException("Address value is required.");
        }

        return value.Trim();
    }

    /// <summary>
    /// しきい値が有効かを検証します。
    /// </summary>
    /// <param name="threshold">検証対象のしきい値。</param>
    private static void ValidateThreshold(int threshold)
    {
        if (threshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(threshold), threshold, "Threshold must be greater than zero.");
        }
    }
}
