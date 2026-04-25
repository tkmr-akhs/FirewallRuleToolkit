namespace FirewallRuleToolkit.Cli;

/// <summary>
/// CLI のヘルプ説明文を提供します。
/// </summary>
internal static class CommandDescriptions
{
    public static string Root =>
        """
        Palo Alto Networks 形式の CSV を作業用データベースへ取り込み、
        ルールの分解・統合・出力・統計確認を行う CLI ツールです。

        一般的な実行順:
          1. import  オブジェクト CSV とセキュリティ ポリシー CSV を取り込みます。
          2. atomize ルールを原子的な単位へ展開します。
          3. merge   atomic 化した結果を条件単位で再統合します。
          4. test    merge 結果が atomic の挙動を保持しているかを検査します。
          5. export  atomic / merged の結果を CSV として書き出します。
          6. stat    現在のデータベース状態と件数を確認します。

        グローバル オプションは各サブコマンドでも利用できます。
        コマンドラインで未指定の値は --config で指定した JSON 設定ファイルから読み込みます。
        """;

    public static string Import =>
        """
        Palo Alto Networks 形式の CSV を作業用 SQLite データベースへ取り込みます。
        未解決のアドレス / サービス参照と各種オブジェクト定義を保存し、
        後続の atomize で参照解決できる状態を作るため、
        後続の atomize / merge / export / stat の起点になるコマンドです。

        必要な入力:
          - セキュリティ ポリシー CSV
          - アドレス CSV
          - アドレス グループ CSV
          - サービス CSV
          - サービス グループ CSV
        """;

    public static string Atomize =>
        """
        import 済みのセキュリティ ポリシーを対象に、
        送信元 / 宛先アドレス、アプリケーション、サービスの組み合わせを
        atomic_security_policies として展開します。

        threshold は範囲を単一値へ展開するしきい値です。
        要素数が threshold 未満なら単一値へ分解し、threshold 以上なら範囲のまま保持します。
        """;

    public static string Merge =>
        """
        atomize 済みの Atomic ポリシーを、ゾーン・アプリケーション・アクション・
        サービス種別などの条件単位で統合し、merged_security_policies を生成します。
        先頭のポート マージでは、Kind が同じであれば IP プロトコル番号の違いを吸収します。
        Allow 以外のルールは atomic のまま扱い、同じ元ルール由来の要素だけを merged 側で束ねます。
        先行ルールが後続ルールを完全に覆う場合は、元インデックスが小さい側を採用します。

        wkport と wkpthreshold を併用すると、よく使われる宛先ポートだけで構成された
        小さなポート集合について、宛先アドレス集約を抑止できます。
        宛先ポートがすべて wkport に含まれ、かつ、その個数が wkpthreshold 未満のときだけ
        宛先アドレス集約を行いません。

        merge では hspercent の指定が必須です。
        高一致率再編成で必要な宛先 / サービスの一致率をパーセントで調整でき、
        設定ファイルまたはコマンドライン オプションで指定してください。
        """;

    public static string Export =>
        """
        作業用データベースから CSV を出力します。
        Atomic は atomize 結果、Merged は merge 結果を出力します。
        Merged 出力時は import 済みのアドレス グループ情報がある場合、
        可能な範囲でグループ表現を再利用します。
        """;

    public static string Test =>
        """
        merge 済みの merged_security_policies が、
        shadowed 除去後の Atomic ポリシーの挙動を保持しているかを検査します。
        含まれる merged が見つからない場合や Action が異なる場合はログへ記録します。
        shadowed に落ちた Atomic の不一致は informational、それ以外は warning として扱います。
        """;

    public static string Stat =>
        """
        現在の作業用データベースの状態を表示します。
        import / atomize / merge の各段階が完了済みかどうかと、
        主要テーブル件数を確認できます。
        """;
}
