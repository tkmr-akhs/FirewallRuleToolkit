# TODO

## タグ一覧

| タグ名 | 短縮タグ | 意味 |
| --- | --- | --- |
| バグ | `[bug]` | 現仕様・期待動作に対する誤動作。実務データで誤った結果になる可能性があるもの。 |
| 要リファクタリング | `[ref]` | 動いてはいるが、設計・責務・依存関係・テスト容易性に問題があるもの。 |
| 仕様改善 | `[spec]` | 仕様の明確化、境界条件の整理、仕様上の矛盾、現仕様として明確だが著しく不便なものの見直し。 |
| 必須機能不足 | `[req]` | 実務利用に必要だが、現時点で機能として欠けているもの。 |
| 利便性向上 | `[ux]` | 結果の見やすさ、調査しやすさ、操作性、運用しやすさの改善。 |

このメモは、コードレビューで見つかったが今回対応しなかった指摘点を整理したものです。

対応済みの `policy index` 型整理、Domain entity の必須性整理、参照モデルと解決済み値モデルの分離は含めません。

## 高優先度

- [ ] [req] Palo Alto ルール条件の未取込列を扱う
  - 現在は zone / address / application / service / action / groupId を中心に取り込みます。
  - source user、URL category、schedule、tag、profile、disabled、negate、device / vsys などを無視すると、実務上は別条件のルールを同一視する可能性があります。
  - 方針案: 未対応列に有効値があれば import で止める、または Domain モデルへ条件として追加する。

- [ ] [bug] import / atomize 後の派生データを無効化する
  - `import` 後に atomic / merged / metadata が残り得ます。
  - `atomize` 後にも既存 merged が残り得ます。
  - `stat` / `export` はテーブル存在だけを見ているため、古い整理結果を利用する危険があります。

- [ ] [bug] `stat` の段階表示を処理フローの依存関係に合わせる
  - 現在は merged テーブルが存在すれば、atomize が未実行扱いでも `Merge: completed` と表示できます。
  - `import` -> `atomize` -> `merge` の依存関係と表示がずれると、DB の状態を誤認しやすくなります。
  - 方針案: 下流段階は上流段階が completed のときだけ completed 判定する、または成果物の世代情報で整合性を確認する。

- [ ] [ux] merge / test の警告を終了コードに反映できるようにする
  - action range overlap や test warning があっても現在は成功終了します。
  - CI や定期実行で危険な整理結果を見逃しやすくなります。
  - 方針案: `--strict` または `--fail-on-warning` を追加する。

## 中優先度

- [ ] [spec] service `any` と `Kind` 指定の包含関係を整理する
  - `any` service は `Kind = null`、`application-default` などは `Kind` 指定として扱われます。
  - containment や merge partition が `Kind` を厳密に見るため、期待する「any がすべてを含む」動きとずれる可能性があります。

- [ ] [ux] AddressGroupCompactor の最適性を改善する
  - 現在は大きい group から貪欲に exact subset を選びます。
  - 重なりのある group 候補では、より自然な組み合わせを逃す可能性があります。

- [ ] [ref] 正規化処理の責務を整理する
  - Palo Alto CSV reader と Domain parser の両方に address / service 正規化があります。
  - `any` / `ANY` などの扱いが入口によって変わる箇所があります。
  - 方針案: 正規化を Domain 側へ寄せ、Infra は入力形式の読み取りに集中させる。

- [ ] [ref] Domain から `ILogger` 依存を外す
  - Domain service が `Microsoft.Extensions.Logging` とローカル logging helper に依存しています。
  - 業務判定と診断出力が密結合になり、Domain 単体での再利用性が下がります。
  - 方針案: Domain はイベント / 診断結果を返し、App 層で logger へ変換する。

- [ ] [spec] well-known port 制御の値検証を強化する
  - `wkpthreshold = 0` が通り、実質的に制御が無効化されます。
  - `wkport = 0` も実務上の意味が薄い可能性があります。
  - 方針案: threshold は 1 以上、port は必要に応じて 1 以上 65535 に制限する。

## 低優先度

- [ ] [ref] Domain value object の invariant を強化する
  - `AddressValue` や `ServiceValue` は init-only ですが、範囲の大小関係や上限値を型自身では保証していません。
  - JSON / SQLite 復元時も不正値が入り得ます。
  - 方針案: factory / constructor 化、または復元境界での検証を追加する。

- [ ] [ref] Composition root の配置と App 層の Infra 依存を整理する
  - `App.Composition` が SQLite / CSV / Palo Alto reader を直接生成しています。
  - 「App 層はユースケース、具象配線は入口側」と見るなら、Composition は CLI 直下または top-level Composition へ分離したほうが境界が明確になります。
  - 方針案: App.UseCases は Port と純粋な入力値だけを受け取り、具象 Infra の組み立ては CLI / composition root 側へ移す。

- [ ] [bug] `ExportTarget` / `LogType` の未定義 flag 値を拒否する
  - config JSON などから数値 enum を渡すと、未定義 bit が通る可能性があります。
  - `target: 4` のような値が「非 None だが何も export しない」状態を作れます。

- [ ] [ref] App / UseCase から global logger 依存を外す
  - UseCase が `ProgramLogger` を直接参照しており、App 層の再利用性とテスト容易性が下がっています。
  - 方針案: logger を引数または App service として注入する。

- [ ] [ref] `GroupId` の名前で由来と用途を明確にする
  - 実体は Palo Alto CSV の `ルールの使用状況 内容` から切り出した merge grouping 用の値です。
  - 汎用的な `GroupId` という名前だけでは、アドレス グループやサービス グループとの区別がつきにくく、何を表す ID か読み取りづらいです。
  - 方針案: 挙動は変えず、`RuleUsageGroupId` や `MergeGroupId` などへ改名する。

- [ ] [bug][ux] SQLite availability check の副作用を減らす
  - 一部の availability check は DB ファイル作成を伴う可能性があります。
  - 読み取り確認で空 DB が作られると、利用者の混乱につながります。

- [ ] [spec] CSV header 重複時の挙動を検証する
  - header が重複した場合、後勝ちになる可能性があります。
  - 入力ミスを早期検出するなら、重複 header は読み取りエラーにするほうが安全です。

- [ ] [ux] shadowed ルールを独立した整理レポートとして出力する
  - 現在は shadowed な Atomic の trace が前方ルールへ吸収され、merged CSV だけでは「なぜ消えたか」が追いにくいです。
  - 削除候補、順序見直し候補、影響元ルールを別レポートとして出せると実務レビューしやすくなります。

## 対応しない事項

- [spec] `GroupId` の扱いを堅くする
  - 現在は `ルールの使用状況 内容` の `|` より前を使い、取得できない場合は空文字列になります。
  - 空文字列に寄ると、本来別の整理単位にしたいルールが同じ `GroupId` として扱われる可能性があります。
  - 方針案: `GroupId` 必須モード、明示的な group 無視モード、列形式検証を追加する。
  - 結論: この挙動は意図的な仕様です。

- [ux] merged の traceability を exact source set で保持する
  - 現在は `MinimumIndex` / `MaximumIndex` と `OriginalPolicyNames` が中心です。
  - 間に別 action があると action overlap warning が過検知になり、CSV から正確な元 index 集合を復元しにくいです。
  - 方針案: `OriginalPolicyIndices` の集合を持つ。
  - 結論: インデックス値は衝突チェックのためであり、トレーサビリティ情報ではありません。トレース情報はポリシー名で十分です。

- [ux] export 時に既存 address object 名を復元する
  - address group compaction はありますが、単体 address object 名の復元はありません。
  - 実務レビューでは raw IP / CIDR より既存オブジェクト名のほうが扱いやすいです。
  - 結論: アドレス分解などに起因として、中途半端な対応となりえます。エクスポートしたCSVに基づいてアドレスオブジェクトを利用者が手動で再整理したほうがよいです。
