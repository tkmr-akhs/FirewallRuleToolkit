namespace FirewallRuleToolkit.Domain.Ports;

/// <summary>
/// ツール実行に伴うメタデータを永続化します。
/// </summary>
public interface IToolMetadataRepository
{
    /// <summary>
    /// リポジトリが利用可能な状態かを確認します。
    /// </summary>
    void EnsureAvailable();

    /// <summary>
    /// atomize 実行時に使用したしきい値を保存します。
    /// </summary>
    /// <param name="threshold">保存するしきい値。</param>
    void SetAtomizeThreshold(int threshold);

    /// <summary>
    /// 保存済み atomize しきい値を取得します。
    /// </summary>
    /// <param name="threshold">取得できた場合に設定されるしきい値。</param>
    /// <returns>取得できた場合は <see langword="true"/>。</returns>
    bool TryGetAtomizeThreshold(out int threshold);

    /// <summary>
    /// 保持済みメタデータをすべて削除します。
    /// </summary>
    void Clear();
}
