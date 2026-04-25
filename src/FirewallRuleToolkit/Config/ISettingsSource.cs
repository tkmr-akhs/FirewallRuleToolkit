namespace FirewallRuleToolkit.Config;

/// <summary>
/// 設定ファイルの読み込み元を表します。
/// </summary>
public interface ISettingsSource
{
    /// <summary>
    /// 指定したパスから設定を読み込みます。
    /// </summary>
    /// <param name="path">設定ファイル パス。</param>
    /// <param name="cancellationToken">キャンセル通知。</param>
    /// <returns>読み込んだ設定。存在しない場合は <see langword="null"/>。</returns>
    Task<Settings?> LoadAsync(string path, CancellationToken cancellationToken);
}
