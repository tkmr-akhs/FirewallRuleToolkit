namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// サービス条件集合を、設定値としての同一性に基づいて操作します。
/// </summary>
internal static class ServiceConditionSetOperations
{
    /// <summary>
    /// 設定値として一致するサービス条件を吸収先へ追加します。
    /// </summary>
    /// <param name="target">吸収先集合。</param>
    /// <param name="source">吸収元集合。</param>
    public static void AbsorbConfiguredIdentity(HashSet<ServiceValue> target, IEnumerable<ServiceValue> source)
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
    public static HashSet<ServiceValue> UnionByConfiguredIdentity(
        IEnumerable<ServiceValue> left,
        IEnumerable<ServiceValue> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<ServiceValue>(left);
        result.UnionWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく共通部分を作成します。
    /// </summary>
    /// <param name="left">左集合。</param>
    /// <param name="right">右集合。</param>
    /// <returns>共通部分集合。</returns>
    public static HashSet<ServiceValue> IntersectByConfiguredIdentity(
        IEnumerable<ServiceValue> left,
        IEnumerable<ServiceValue> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<ServiceValue>(left);
        result.IntersectWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく差分を作成します。
    /// </summary>
    /// <param name="source">差分元集合。</param>
    /// <param name="excluded">除外対象集合。</param>
    /// <returns>差分集合。</returns>
    public static HashSet<ServiceValue> SubtractByConfiguredIdentity(
        IEnumerable<ServiceValue> source,
        IEnumerable<ServiceValue> excluded)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(excluded);

        var result = new HashSet<ServiceValue>(source);
        result.ExceptWith(excluded);
        return result;
    }

    /// <summary>
    /// サービス条件集合を、設定値としての同一性に基づく安定シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象サービス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    public static string CreateConfiguredIdentitySignature(IEnumerable<ServiceValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return ConfiguredIdentitySignatureBuilder.BuildSequenceSignature(
            values
                .OrderBy(static value => value.ProtocolStart)
                .ThenBy(static value => value.ProtocolFinish)
                .ThenBy(static value => value.SourcePortStart)
                .ThenBy(static value => value.SourcePortFinish)
                .ThenBy(static value => value.DestinationPortStart)
                .ThenBy(static value => value.DestinationPortFinish)
                .ThenBy(static value => value.Kind, StringComparer.Ordinal),
            static (builder, value) =>
            {
                builder.Append(value.ProtocolStart);
                builder.Append('-');
                builder.Append(value.ProtocolFinish);
                builder.Append('/');
                builder.Append(value.SourcePortStart);
                builder.Append('-');
                builder.Append(value.SourcePortFinish);
                builder.Append('/');
                builder.Append(value.DestinationPortStart);
                builder.Append('-');
                builder.Append(value.DestinationPortFinish);
                builder.Append('/');
                ConfiguredIdentitySignatureBuilder.AppendString(builder, value.Kind);
            });
    }
}
