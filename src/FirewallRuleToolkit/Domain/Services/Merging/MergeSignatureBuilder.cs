using System.Text;

namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge の grouping に使うシグネチャを構築します。
/// </summary>
internal static class MergeSignatureBuilder
{
    /// <summary>
    /// アドレス条件集合を configured identity シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象アドレス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string AddressConfiguredIdentitySet(IEnumerable<AddressValue> values)
    {
        return AddressConditionSetOperations.CreateConfiguredIdentitySignature(values);
    }

    /// <summary>
    /// サービス条件集合を configured identity シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象サービス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string ServiceConfiguredIdentitySet(IEnumerable<ServiceValue> values)
    {
        return ServiceConditionSetOperations.CreateConfiguredIdentitySignature(values);
    }

    /// <summary>
    /// アプリケーション条件集合を configured identity シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象アプリケーション列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string ApplicationConfiguredIdentitySet(IEnumerable<string> values)
    {
        return ApplicationConditionSetOperations.CreateConfiguredIdentitySignature(values);
    }

    /// <summary>
    /// 通常の文字列集合を Ordinal 比較の安定シグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象文字列列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string OrdinalStringSet(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        return ConfiguredIdentitySignatureBuilder.BuildSequenceSignature(
            values.OrderBy(static value => value, StringComparer.Ordinal),
            static (builder, value) => ConfiguredIdentitySignatureBuilder.AppendString(builder, value));
    }

    /// <summary>
    /// 単一文字列を Ordinal 比較の安定シグネチャへ変換します。
    /// </summary>
    /// <param name="value">対象文字列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string OrdinalStringValue(string? value)
    {
        var builder = new StringBuilder();
        ConfiguredIdentitySignatureBuilder.AppendString(builder, value);
        return builder.ToString();
    }
}
