namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// アプリケーション条件集合を、設定値としての同一性に基づいて操作します。
/// </summary>
internal static class ApplicationConditionSetOperations
{
    /// <summary>
    /// 設定値として一致するアプリケーション条件を吸収先へ追加します。
    /// </summary>
    /// <param name="target">吸収先集合。</param>
    /// <param name="source">吸収元集合。</param>
    public static void AbsorbConfiguredIdentity(HashSet<string> target, IEnumerable<string> source)
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
    public static HashSet<string> UnionByConfiguredIdentity(
        IEnumerable<string> left,
        IEnumerable<string> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<string>(left, StringComparer.Ordinal);
        result.UnionWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく共通部分を作成します。
    /// </summary>
    /// <param name="left">左集合。</param>
    /// <param name="right">右集合。</param>
    /// <returns>共通部分集合。</returns>
    public static HashSet<string> IntersectByConfiguredIdentity(
        IEnumerable<string> left,
        IEnumerable<string> right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        var result = new HashSet<string>(left, StringComparer.Ordinal);
        result.IntersectWith(right);
        return result;
    }

    /// <summary>
    /// 設定値としての同一性に基づく差分を作成します。
    /// </summary>
    /// <param name="source">差分元集合。</param>
    /// <param name="excluded">除外対象集合。</param>
    /// <returns>差分集合。</returns>
    public static HashSet<string> SubtractByConfiguredIdentity(
        IEnumerable<string> source,
        IEnumerable<string> excluded)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(excluded);

        var result = new HashSet<string>(source, StringComparer.Ordinal);
        result.ExceptWith(excluded);
        return result;
    }

    /// <summary>
    /// アプリケーション条件集合を、設定値としての同一性に基づく安定シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象アプリケーション列。</param>
    /// <returns>比較用シグネチャ。</returns>
    public static string CreateConfiguredIdentitySignature(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return ConfiguredIdentitySignatureBuilder.BuildSequenceSignature(
            PolicyConditionCanonicalOrder.OrderApplications(values),
            static (builder, value) => ConfiguredIdentitySignatureBuilder.AppendString(builder, value));
    }
}
