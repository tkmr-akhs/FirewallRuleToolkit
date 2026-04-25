namespace FirewallRuleToolkit.Config;

/// <summary>
/// ツール全体の設定を表します。
/// </summary>
public sealed class Settings
{
    /// <summary>
    /// データベース フォルダー パスを取得します。
    /// </summary>
    public string? Database { get; init; }

    /// <summary>
    /// ログ出力設定を取得します。
    /// </summary>
    public Config.LogType? LogType { get; init; }

    /// <summary>
    /// ログ ファイル パスを取得します。
    /// </summary>
    public string? LogFile { get; init; }

    /// <summary>
    /// ログ レベルを取得します。
    /// </summary>
    public LogLevel? LogLevel { get; init; }

    /// <summary>
    /// import サブコマンド設定を取得します。
    /// </summary>
    public ImportSettings Import { get; init; } = new();

    /// <summary>
    /// atomize サブコマンド設定を取得します。
    /// </summary>
    public AtomizeSettings Atomize { get; init; } = new();

    /// <summary>
    /// merge サブコマンド設定を取得します。
    /// </summary>
    public MergeSettings Merge { get; init; } = new();

    /// <summary>
    /// export サブコマンド設定を取得します。
    /// </summary>
    public ExportSettings Export { get; init; } = new();

    /// <summary>
    /// stat サブコマンド設定を取得します。
    /// </summary>
    public StatSettings Stat { get; init; } = new();

    /// <summary>
    /// import サブコマンド設定を表します。
    /// </summary>
    public sealed class ImportSettings
    {
        /// <summary>
        /// 入力 CSV の文字コードを取得します。
        /// </summary>
        public string? Encoding { get; init; }

        /// <summary>
        /// 入力 CSV の BOM 有無を取得します。
        /// </summary>
        public bool? WithBom { get; init; }

        /// <summary>
        /// セキュリティ ポリシー CSV パスを取得します。
        /// </summary>
        public string? SecurityPolicies { get; init; }

        /// <summary>
        /// アドレス CSV パスを取得します。
        /// </summary>
        public string? Addresses { get; init; }

        /// <summary>
        /// アドレス グループ CSV パスを取得します。
        /// </summary>
        public string? AddressGroups { get; init; }

        /// <summary>
        /// サービス CSV パスを取得します。
        /// </summary>
        public string? Services { get; init; }

        /// <summary>
        /// サービス グループ CSV パスを取得します。
        /// </summary>
        public string? ServiceGroups { get; init; }
    }

    /// <summary>
    /// atomize サブコマンド設定を表します。
    /// </summary>
    public sealed class AtomizeSettings
    {
        /// <summary>
        /// 分解時のしきい値を取得します。
        /// </summary>
        public int? Threshold { get; init; }
    }

    /// <summary>
    /// merge サブコマンド設定を表します。
    /// </summary>
    public sealed class MergeSettings
    {
        /// <summary>
        /// 宛先ポート マージを抑止したい既知ポート一覧を取得します。
        /// </summary>
        public string? WkPort { get; init; }

        /// <summary>
        /// 既知ポートだけで構成されるルールを宛先ポートごとに保持するしきい値を取得します。
        /// </summary>
        public uint? WkpThreshold { get; init; }

        /// <summary>
        /// ルールの高類似度を判定するしきい値 (パーセント) を取得します。
        /// </summary>
        public uint? HsPercent { get; init; }
    }

    /// <summary>
    /// export サブコマンド設定を表します。
    /// </summary>
    public sealed class ExportSettings
    {
        /// <summary>
        /// 出力 CSV の文字コードを取得します。
        /// </summary>
        public string? Encoding { get; init; }

        /// <summary>
        /// 出力 CSV の BOM 有無を取得します。
        /// </summary>
        public bool? WithBom { get; init; }

        /// <summary>
        /// 出力する対象を取得します。
        /// </summary>
        public Config.ExportTarget? Target { get; init; }

        /// <summary>
        /// 分解されたセキュリティ ポリシー CSV パスを取得します。
        /// </summary>
        public string? Atomic { get; init; }

        /// <summary>
        /// 集約されたセキュリティ ポリシー CSV パスを取得します。
        /// </summary>
        public string? Merged { get; init; }

    }

    /// <summary>
    /// stat サブコマンド設定を表します。
    /// </summary>
    public sealed class StatSettings
    { }
}
