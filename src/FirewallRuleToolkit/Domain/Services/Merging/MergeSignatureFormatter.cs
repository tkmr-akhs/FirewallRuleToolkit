using System.Text;

namespace FirewallRuleToolkit.Domain.Services.Merging;

/// <summary>
/// merge シグネチャ構築で使う共通フォーマット処理を提供します。
/// </summary>
internal static class MergeSignatureFormatter
{
    /// <summary>
    /// アドレス集合を順序依存しないシグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象アドレス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string BuildAddressSetSignature(IEnumerable<AddressValue> values)
    {
        return BuildSequenceSignature(
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

    /// <summary>
    /// 文字列集合を順序依存しないシグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象文字列列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string BuildStringSetSignature(IEnumerable<string> values)
    {
        return BuildSequenceSignature(
            values.OrderBy(static value => value, StringComparer.Ordinal),
            static (builder, value) => AppendString(builder, value));
    }

    /// <summary>
    /// サービス集合を順序依存しないシグネチャへ変換します。
    /// </summary>
    /// <param name="values">対象サービス列。</param>
    /// <returns>比較用シグネチャ。</returns>
    internal static string BuildServiceSetSignature(IEnumerable<ServiceValue> values)
    {
        return BuildSequenceSignature(
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
                AppendString(builder, value.Kind);
            });
    }

    /// <summary>
    /// 単一文字列をシグネチャ化します。
    /// </summary>
    /// <param name="value">対象文字列。</param>
    /// <returns>シグネチャ文字列。</returns>
    internal static string BuildStringSignature(string? value)
    {
        var builder = new StringBuilder();
        AppendString(builder, value);
        return builder.ToString();
    }

    /// <summary>
    /// 任意の値列をシグネチャ文字列へ変換します。
    /// </summary>
    /// <typeparam name="T">対象値の型。</typeparam>
    /// <param name="values">対象値列。</param>
    /// <param name="appendValue">シグネチャへ追記する処理。</param>
    /// <returns>生成したシグネチャ文字列。</returns>
    private static string BuildSequenceSignature<T>(
        IEnumerable<T> values,
        Action<StringBuilder, T> appendValue)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
        {
            appendValue(builder, value);
        }

        return builder.ToString();
    }

    /// <summary>
    /// 文字列 1 件を長さ付きでシグネチャへ追記します。
    /// </summary>
    /// <param name="builder">追記先ビルダー。</param>
    /// <param name="value">追記対象文字列。</param>
    private static void AppendString(StringBuilder builder, string? value)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var text = value ?? string.Empty;
        builder.Append(text.Length);
        builder.Append(':');
        builder.Append(text);
        builder.Append(';');
    }
}
