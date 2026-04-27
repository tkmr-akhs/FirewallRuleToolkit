using System.Text;

namespace FirewallRuleToolkit.Domain.Services.PolicyConditions;

/// <summary>
/// 設定値としての条件集合を安定したシグネチャへ変換する補助処理です。
/// </summary>
internal static class ConfiguredIdentitySignatureBuilder
{
    /// <summary>
    /// 安定順序へ並べた値列をシグネチャ文字列へ変換します。
    /// </summary>
    /// <typeparam name="T">対象値の型。</typeparam>
    /// <param name="values">対象値列。</param>
    /// <param name="appendValue">シグネチャへ追記する処理。</param>
    /// <returns>生成したシグネチャ文字列。</returns>
    internal static string BuildSequenceSignature<T>(
        IEnumerable<T> values,
        Action<StringBuilder, T> appendValue)
    {
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(appendValue);

        var builder = new StringBuilder();
        foreach (var value in values)
        {
            appendValue(builder, value);
        }

        return builder.ToString();
    }

    /// <summary>
    /// 単一文字列を長さ付きでシグネチャへ追記します。
    /// </summary>
    /// <param name="builder">追記先ビルダー。</param>
    /// <param name="value">追記対象文字列。</param>
    internal static void AppendString(StringBuilder builder, string? value)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var text = value ?? string.Empty;
        builder.Append(text.Length);
        builder.Append(':');
        builder.Append(text);
        builder.Append(';');
    }
}
