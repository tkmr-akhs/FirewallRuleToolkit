using System.Text.Json;
using System.Text.Json.Serialization;

namespace FirewallRuleToolkit.Config;

/// <summary>
/// JSON ファイルから設定を読み込みます。
/// </summary>
public sealed class JsonToolSettingsSource : ISettingsSource
{
    /// <summary>
    /// 指定した JSON ファイルから設定を読み込みます。
    /// </summary>
    /// <param name="path">設定ファイル パス。</param>
    /// <param name="cancellationToken">キャンセル通知。</param>
    /// <returns>読み込んだ設定。</returns>
    public async Task<Settings?> LoadAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        await using var stream = File.OpenRead(path);

        var document = await JsonSerializer.DeserializeAsync<Settings>(
            stream,
            SerializerOptions,
            cancellationToken);

        return document;
    }

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters =
        {
            new JsonStringEnumConverter()
        }
    };
}
