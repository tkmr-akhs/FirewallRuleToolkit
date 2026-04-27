namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// アドレス条件集合を、設定値としての同一性に基づいて操作します。
/// </summary>
internal static class AddressConditionSetOperations
{
    /// <summary>
    /// 設定値として一致するアドレス条件を吸収先へ追加します。
    /// </summary>
    /// <param name="target">吸収先集合。</param>
    /// <param name="source">吸収元集合。</param>
    public static void AbsorbConfiguredIdentity(HashSet<AddressValue> target, IEnumerable<AddressValue> source)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(source);

        target.UnionWith(source);
    }

    /// <summary>
    /// 設定値としての同一性に基づく和集合を作成します。
    /// </summary>
    /// <param name="left">左集合。</param>
    /// <param name="right">右集合。</param>
    /// <returns>和集合。</returns>
    public static HashSet<AddressValue> UnionByConfiguredIdentity(
        IEnumerable<AddressValue> left,
        IEnumerable<AddressValue> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<AddressValue>(left);
        result.UnionWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく共通部分を作成します。
    /// </summary>
    /// <param name="left">左集合。</param>
    /// <param name="right">右集合。</param>
    /// <returns>共通部分集合。</returns>
    public static HashSet<AddressValue> IntersectByConfiguredIdentity(
        IEnumerable<AddressValue> left,
        IEnumerable<AddressValue> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<AddressValue>(left);
        result.IntersectWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく差分を作成します。
    /// </summary>
    /// <param name="source">差分元集合。</param>
    /// <param name="excluded">除外対象集合。</param>
    /// <returns>差分集合。</returns>
    public static HashSet<AddressValue> SubtractByConfiguredIdentity(
        IEnumerable<AddressValue> source,
        IEnumerable<AddressValue> excluded)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(excluded);

        var result = new HashSet<AddressValue>(source);
        result.ExceptWith(excluded);
        return result;
    }

    /// <summary>
    /// アドレス条件集合を、設定値としての同一性に基づく安定シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象アドレス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    public static string CreateConfiguredIdentitySignature(IEnumerable<AddressValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return ConfiguredIdentitySignatureBuilder.BuildSequenceSignature(
            values
                .OrderBy(static value => value.Start)
                .ThenBy(static value => value.Finish),
            static (builder, value) =>
            {
                builder.Append(value.Start);
                builder.Append('-');
                builder.Append(value.Finish);
                builder.Append(';');
            });
    }
}
