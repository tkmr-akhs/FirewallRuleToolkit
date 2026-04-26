# TODO

このファイルは、現時点で見つかっている未対応事項や設計上の検討事項をまとめたものです。

## タグ一覧

| タグ名 | 短縮タグ | 意味 |
| --- | --- | --- |
| バグ | `[bug]` | 現仕様・期待動作に対する誤動作。実務データで誤った結果になるもの。 |
| 要リファクタリング | `[ref]` | 動いてはいるが、設計・責務・依存関係・テスト容易性に問題があるもの。 |
| 仕様改善 | `[spec]` | 仕様の明確化、境界条件の整理、仕様上の矛盾、現仕様として明確だが著しく不便なものの見直し。 |
| 必須機能不足 | `[req]` | 実務利用に必要だが、現時点で仕様として欠けているもの。 |
| 利便性向上 | `[ux]` | 結果の見やすさ、調査しやすさ、操作性、運用しやすさの改善。 |
| 製品試験増強 | `[test]` | 製品試験の考慮不足など。　※ この製品の test 機能とは無関係 |

## 高優先度

- [ ] [ref] 正規化処理の責務を整理する。
  - `SecurityPolicyAtomizer`、`SecurityPolicyMerger`、各 repository / exporter に類似の normalize / distinct / sort が分散している。
  - 方針案: Domain value object の正規化、不変条件、表示順を分けて責務を明確にする。

- [ ] [ref] Domain runner と UseCase の責務境界を整理する。
  - `SecurityPolicyAtomizeRunner` / `SecurityPolicyMergeRunner` / `SecurityPolicyTestRunner` が進捗間隔、スキップ扱い、repository 追記 callback、実行件数集計を持っており、Domain service がバッチ実行手順まで知っている。
  - `SecurityPolicyAtomizer` / `SecurityPolicyMerger` / containment / test 判定の純粋な業務ロジックと、App 側の transaction / progress / warning policy を分けたい。
  - 方針案: Domain は変換・判定結果と diagnostic value を返し、UseCase が列挙、書き込み、進捗、ログ変換を担当する。

- [ ] [ref] address / service / application の集合演算 API を Domain に集約する。
  - containment は `SecurityPolicyContainment`、差分/和集合は `HighSimilarityPolicyRecomposer`、CIDR 判定や表示用変換は exporter 側に分散している。
  - 方針案: `AddressRangeSet` / `ServiceConditionSet` / `ApplicationSet` などに contains / union / intersect / subtract / format 用の明示的な責務境界を持たせる。

- [ ] [ux] merged service export のプロトコル範囲表記を整理する。
  - `CsvMergedSecurityPolicyWriter` はプロトコル範囲の両端をプロトコル名へ変換するため、`1-17` が `icmp-udp` のような表記になり得る。
  - `ServiceValueParser` の直指定サービス parser はプロトコル名を範囲端点として扱わないため、レビュー用としても再利用用としても意味が読み取りづらい。
  - 方針案: 範囲は数値表記に固定し、プロトコル名は単一値だけに使う。

- [ ] [ux] merged export の address / service 表示順を安定化する。
  - セット由来の値が出力される場合、差分レビューでノイズになる可能性がある。
  - 方針案: Domain の canonical order と exporter の表示順を定義する。

- [ ] [bug] `merged` の読み出し順と first-hit 検証順を揃える。
  - `SecurityPolicyTestRunner` は `MinimumIndex`、`MaximumIndex` の順で first-hit を選ぶ一方、`SqliteMergedSecurityPolicyRepository.GetAll()` は `MinimumIndex`、`rowid` の順で返す。
  - 同じ `MinimumIndex` を持つ merged が複数ある場合、`test` の判定順と export CSV の表示・適用順がずれる可能性がある。
  - 方針案: merged policy の canonical order を Domain 側で定義し、repository / exporter / test で共有する。

## 中優先度

- [ ] [spec] 高一致率再編成の集合演算モデルを整理する。
  - `HighSimilarityPolicyRecomposer` が文字列集合の完全一致を中心に扱っており、CIDR / IP range の包含関係を活かせていない。
  - 共通部と残差を作ったあと、残差同士で再度共通化できるケースを拾えていない。
  - 再編成で作った共通部や残差が、通常の service / source address / destination address 統合でさらにまとめられる形になっても、再評価されない。
  - 同点候補の選択が入力順に依存するため、同じ集合でも前段の出力順で再編成結果が変わる可能性がある。
  - 方針案: address / service / application の差分を Domain の範囲演算として表現し、残差の再評価を明示的なフェーズにする。

- [ ] [req] `test` を merged 側からも検証し、first-hit 照合を修正する。
  - 現在は atomic から見て merged が見つかるかを中心に確認しており、merged に余計な許可が混入した場合を検出しづらい。
  - first-hit の比較も、「後続に同じ動作のルールがある」だけではなく、元と merged の最初に一致するルール同士を比較する必要がある。
  - 方針案: atomic -> merged と merged -> atomic の双方向 containment と、first-hit equivalence を分けて検証する。

- [ ] [req] `import` / `atomize` で条件軸が空になりうる。
  - 空の source / destination / service / application は atomize 結果を 0 件にし、ルール欠落につながる。
  - 方針案: import 時に拒否するか、Domain で policy condition の不変条件として表現する。
  - 備考: Palo Alto 機の CSV レポート機能で取り出したものを使用する想定であり、防御的検証という位置づけ

- [ ] [bug] `SecurityPolicyAction` と flag enum が未定義値を受け入れる。
  - `SecurityPolicyAction` は任意の整数で生成でき、未定義 action が merge / export に流入できる。
  - `ExportTarget` / `LogType` などの `[Flags]` enum も未定義ビットを受け取ると、何もしない成功や意図しない出力になり得る。
  - 設定 JSON の enum deserialization も整数値を受け取れるため、CLI option と設定ファイルの両方で検証が必要。
  - 方針案: CLI parse 境界または App 層で enum validation を共通化する。

- [ ] [spec] CSV 入力スキーマと parser error context を整理する。
  - duplicate header がある場合、どちらの列が採用されるか不明確。
  - Palo Alto CSV の空ヘッダー index 列を前提にしており、列ずれ時の診断が弱い。
  - quote の開始/終了判定が `CsvRecordReader` と `CsvRecordParser` に分かれており、不正 quote でレコード境界とエラー行番号がずれる可能性がある。
  - malformed quote / record length mismatch などの CSV 破損時に、行番号と列名を含むエラーへ寄せたい。

- [ ] [spec] `AddressGroupCompactor` の候補生成・復元方針を整理する。
  - 現在の compaction は局所的な貪欲探索に近く、グループ数やメンバー重複の最小化が保証されていない。
  - 入力順や既存グループ定義に出力が依存し、同じ値集合でも結果が変わる可能性がある。
  - 単一メンバー group を復元するかどうかも compaction の責務に混ざっている。
  - 候補名は `IReadRepository<AddressGroupMembership>`、展開内容は `ILookupRepository<IReadOnlyList<string>>` から取得しており、2 つの入力源がずれると候補集合が実データと不整合になる。
  - 候補構築時に group 名そのものを通常の `AddressReferenceResolver` へ渡しているため、group 名が `any` や address object 名と衝突すると、group メンバーではなく組み込み値または object 値として解決され得る。
  - 候補構築時に全 group を解決するため、実際の export 対象で使わない group の不備でも merged export 全体が失敗し得る。
  - exact な `HashSet<AddressValue>` の subset 判定だけで圧縮するため、CIDR と IP range の等価性や包含関係、atomize threshold による分解粒度差を使った復元ができない。
  - 方針案: 最適化目標、stable tie-break、復元対象を仕様として分ける。

- [ ] [req] `import` 入力検証を横断的に強化する。
  - 空の address / service group は後段で条件が欠落する原因になる。
  - object 名と group 名の重複、未定義参照、循環参照を import 時にまとめて検出したい。
  - 重複キーや object / group 名衝突を SQLite 制約や辞書構築例外任せにせず、明示的なエラーまたは警告にする。
  - 参照リストは trim される一方、定義名やポリシー名は raw 値を保持する箇所があり、前後空白で lookup がずれる可能性がある。
  - サービス定義の空 source / destination port は現状 `any` に補完されるため、protocol ごとに許容する空値とエラーにする空値を分けたい。
  - 方針案: import validation report を導入し、repository 保存前に検証する。

- [ ] [ux] shadowed rules report を出す。
  - merge / test の過程で検出した shadowed rule をユーザーが確認できる形にする。
  - 方針案: `stat` または dedicated report command で出力する。

- [ ] [ux] `test` の warning / info を詳細化する。
  - どの atomic rule、どの merged rule、どの条件軸で差分が出たかを追いやすくする。
  - 方針案: rule id / sequence / axis / expected / actual を含める。

- [ ] [ux] action range overlap warning の診断情報を詳細化する。
  - 現在の `SecurityPolicyMergeRunResult.ActionRangeOverlap` は action と最小/最大 index だけを持つため、どの merged rule / 元ポリシー名 / 条件が衝突したかをログから追いにくい。
  - 方針案: overlap 判定用の結果に `OriginalPolicyNames`、`GroupId`、代表条件、merged の識別子を含めるか、詳細レポートへ出力する。


## 低優先度

- [ ] [ux] 成果物の世代管理がなく、古い派生データが使われる。
  - `import` 後も以前の `atomic` / `merged` / metadata / stat が残ると、新しい入力に対して古い派生データを使えてしまう。
  - `atomize` 後も以前の `merged` が残ると、古い atomic から作られた結果を export / test できてしまう。
  - `stat` は処理フローの依存関係を表現し、`atomic` がない状態で `merged` だけを表示するような誤解を避ける。
  - `merge` の実行パラメーターも metadata / stat で確認できるようにし、前回結果との差を追えるようにする。
  - 方針案: repository lifecycle に stage generation を導入し、上流成果物更新時に下流成果物を無効化する。
  - 備考: 利用者は不特定多数ではなく開発者自身と近縁者だけを想定。当面は古い派生データが残存することを理解したうえで使用する。

- [ ] [ux] warning / skip を strict mode で失敗扱いにできるようにする。
  - `merge` / `test` の警告が終了コードへ反映されず、CI で検出しづらい。
  - `atomize` のスキップ件数も成功扱いのままなので、入力漏れを見逃しやすい。
  - 方針案: 既定は互換性維持、`--strict` などで warning / skip を非 0 終了にする。

- [ ] [ux] action 順序境界を越える Allow 統合を抑止する CLI option を追加する。
  - 既定では現行どおり、異なる action の元 index 範囲衝突を merge 後 warning として検出する。
  - 必要な場合だけ、Deny などの非 Allow を partition 境界として扱う保守的な merge mode を選べるようにする。
  - 方針案: `merge` に `--split-on-action-boundary` などの option を追加する。

- [ ] [ux] well-known port 制御の `wkport` 値検証を強化する。
  - `wkport = 0` は実務上の意味が薄く、入力ミスとして検出したほうが親切。
  - 方針案: `wkport` は 1 以上 65535 以下に制限し、`wkpthreshold = 0` は許容する。

- [ ] [ux] `atomize` の組み合わせ爆発を検出して警告する。
  - address / service / application の直積が大きい入力で、想定外に大量の atomic rule が生成される。
  - 方針案: 予測件数を事前計算し、閾値超過時に warning / confirmation option を出す。

- [ ] [ux] 参照解決後の重複値を atomize 前に除去する。
  - 複数の group 経由で同じ address / service が展開されると、同等 atomic rule が増える。
  - 方針案: resolved value set と display name set を分け、値集合は重複排除する。

- [ ] [ux] merged export のアドレスグループ再利用を任意化する。
  - 既存 address group 名を再利用すると、元設定と同名で中身の違う group を出力する可能性がある。
  - 現在は merged export 用 writer の生成時に `AddressGroupCompactor` を必ず作るため、merged table があっても import 済み address group と atomize threshold metadata がないと export できない。
  - 方針案: 既定は安全側で新規名または raw address を出力し、既存名再利用はオプションにする。group 情報が利用可能な場合だけ compaction を有効化する。

- [ ] [ux] SQLite 利用可否チェックの副作用をなくす。
  - availability check がファイル作成や schema 作成を伴う場合、dry な確認にならない。
  - 方針案: 接続可否、schema 初期化、repository 作成を分ける。

- [ ] [ux] 不正な encoding option のエラーを分かりやすくする。
  - 現在は .NET の encoding lookup 例外がそのまま出る可能性がある。
  - 方針案: 利用可能な代表値とともに CLI error として出す。

- [ ] [ref] `Program.NormalizeArguments` の責務を整理する。
  - CLI 引数の互換変換と parse 前処理が増えると、System.CommandLine との境界が曖昧になる。
  - 方針案: legacy alias 変換、既定値、parse error を分ける。

- [ ] [spec] service `any` と `Kind` 指定の包含関係を整理する
  - `any` service は `Kind = null`、`application-default` などは `Kind` 指定として扱われます。
  - containment や merge partition が `Kind` を厳密に見るため、期待する「any がすべてを含む」動きとずれる可能性があります。

- [ ] [ref] Palo Alto の Service 列と解決後サービス条件のモデルを分ける。
  - Palo Alto の Service 列には `any`、`application-default`、サービス object 名、サービス group 名、直接指定サービスが入る。
  - 一方、atomize / merge が必要とするのは、プロトコル番号・送信元ポート・宛先ポートへ展開できるサービス条件である。
  - 現状は Service 列の特殊値や、リポジトリで解決できなかった文字列を `ResolvedService.Kind` に載せる経路があり、入力表現と解決後表現の境界が読み取りづらい。
  - 空ポートのサービス定義の扱いも、この境界を決めたうえで整理する。
  - 備考: 未定義サービス参照を `Kind` として許容する方針自体は「対応しないと決定した事項」に含め、ここでは入力表現と解決後条件の責務分離だけを扱う。
  - 方針案: import 時の参照値、名前付き `ServiceDefinition`、解決後のサービス条件、Palo Alto 特殊値を別概念として表現する。

- [ ] [ref] shadow 判定と `GroupId` 境界・命名を整理する。
  - `GroupId` が再編成候補の集合単位なのか、最終ルールの由来なのかがコードから読み取りづらい。
  - shadow 判定は `GroupId` を見ない一方、統合 signature は `GroupId` を見るため、別 `GroupId` の後続ルールが先行ルールへ吸収されたときに最終 `GroupId` が生存側へ寄る。
  - 方針案: `SourceSetId` / `MergePartitionId` / `OriginGroupId` など、用途を表す名前へ分ける。

- [ ] [ref] `merge` / `test` の順序契約を Domain 側で表現する。
  - `Sequence` に依存する処理と、集合として扱える処理の境界が曖昧。
  - `SecurityPolicyMergeRunner` / `SecurityPolicyTestRunner` は `IAtomicPolicyMergeSource.GetAllOrderedForMerge()` 相当の順序を前提にするが、型としては `IEnumerable<AtomicSecurityPolicy>` であり、順序違反を検出しない。
  - 方針案: order-sensitive な rule set と unordered な rule set を型または service 境界で分ける。

- [ ] [ref] merge partition と merge eligibility signature の概念を分ける。
  - `MergePartitionKey` は runner が入力を flush するための連続性キーだが、実際に統合可能かどうかは各 merger の signature (`Action` / `GroupId` / `Application` などを含む) で決まる。
  - 「partition」という名前だけだと、業務上の整理単位、shadow 判定範囲、統合可否条件が同じ概念に見えやすい。
  - 方針案: `MergeStreamPartitionKey` / `MergeEligibilitySignature` などへ分け、処理フェーズごとの境界を明文化する。

- [ ] [ref] policy condition collection の不変条件を Domain 型で表現する。
  - `ImportedSecurityPolicy` / `ResolvedSecurityPolicy` / `MergedSecurityPolicy` が zone / address / application / service の集合を生の list / set として持つため、空集合、空白値、重複、順序依存の扱いが各処理へ散っている。
  - 方針案: `PolicyConditionSet` や `NonEmptyConditionSet<T>` のような型を導入し、空禁止、正規化、canonical order、比較規約を集約する。

- [ ] [ref] `ResolvedAddress` / `ResolvedService` の役割と名前を整理する。
  - 実際には「解決済み」だけでなく、名前表示・値集合・元参照の混合表現になっている。
  - 方針案: `Resolved*`、`Display*`、`Expanded*` などの概念を分ける。

- [ ] [ref] logger 依存を層境界から外す。
  - Domain service が `ILogger` に依存しており、Domain が Microsoft.Extensions.Logging に寄っている。
  - `SecurityPolicyAtomizer` / `SecurityPolicyAtomizeRunner` / `SecurityPolicyMergeRunner` / `SecurityPolicyTester` / `SecurityPolicyTestRunner` には保持しているだけの logger field があり、診断責務の所在をさらに読みにくくしている。
  - App / UseCase でも `ProgramLogger` の global access が残っており、テストや並列実行時の分離が弱い。
  - 方針案: Domain event / diagnostic sink / App 側 observer などへ寄せる。

- [ ] [ref] SQLite schema lifecycle を明示する。
  - `EnsureSchema()` が repository ごとに呼ばれ、schema 変更や migration の責務が分散している。
  - 方針案: DB 初期化 service または migration service に寄せる。

- [ ] [ref] Domain value object の不変条件を強める。
  - `AddressValue` / `ServiceValue` / `ServiceDefinition` などで、生成後に無効状態を持てないようにする。
  - 方針案: factory / parse result / validation error を整理する。

- [ ] [ref] Composition root と App 層の Infra 依存を再点検する。
  - CLI 層で repository 実装を組み立てるのはよいが、App 層が Infra 型へ寄る箇所がないか確認する。
  - 方針案: App は ports と Domain service のみを見る形に寄せる。

- [ ] [ref] UseCase の戻り値と前提チェックを CLI 境界から切り離す。
  - `ImportUseCase` / `MergeUseCase` などが `int` の終了コードを返しており、UseCase が CLI 実行形態を知っている。
  - Composition と UseCase の双方で `EnsureAvailable()` を呼ぶ箇所があり、前提チェック、例外変換、repository 生成の責務が散っている。
  - 方針案: UseCase は実行結果 value を返し、CLI / Composition 側で終了コードと利用者向けエラーへ変換する。前提チェックは composition boundary か UseCase boundary のどちらかへ寄せる。

- [ ] [ref] ツール実行 metadata の Port 所属を整理する。
  - `IToolMetadataRepository` は現状 atomize threshold を保持するために使われ、merged export の address group compaction がその値に依存している。
  - ツール実行パラメーター、成果物世代、入力ソース情報が今後増える場合、`ToolMetadata` という汎用名だけでは責務境界が曖昧になりやすい。
  - 方針案: run state / artifact metadata / source metadata のように責務名へ寄せる。

- [ ] [ref] `IWriteRepository` の lifecycle と transaction 境界を整理する。
  - 書き込み repository の commit / rollback / dispose の責務が実装依存に見える。
  - `IWriteRepositorySession` が Domain Port として具体テーブル一式を公開しており、UseCase 横断の永続化レイアウトが Domain 側へ漏れている。
  - 方針案: unit of work と repository を分けるか、atomic repository 操作として明示する。

- [ ] [ref] `atomize` の入力不備と実装例外を分ける。
  - 入力データの問題とプログラム不変条件違反が同じ例外カテゴリに見える箇所がある。
  - 方針案: domain validation error と internal error を分ける。

- [ ] [ref] 範囲終端を表す名前を統一する。
  - アドレス / サービス範囲は主に `Start` / `Finish`、index range は `MinimumIndex` / `MaximumIndex` を使っている。
  - 現状は大きく崩れていないが、今後 `End` / `To` / `Max` を増やすと inclusive / exclusive が読み取りづらくなる。
  - 方針案: inclusive range なら `Start` / `EndInclusive` などに寄せる。

- [ ] [ref] `GlobalUsings` の層依存を点検する。
  - global using により、Domain から参照すべきでない namespace が見えやすくなっていないか確認する。
  - 方針案: project ごとに必要最小限へ絞る。

- [ ] [ref] `SqliteAtomicPolicyRepository.GetAllOrderedForMerge` の transaction 境界を確認する。
  - merge 中に複数テーブルを読む場合、snapshot consistency を保証する必要がある。
  - transaction 付き repository として生成された場合でも `GetAllOrderedForMerge()` は `DatabasePath` から別接続を開くため、将来セッション内で使うと未コミット内容を読めず、同じ repository 型の契約として分かりづらい。
  - 方針案: read transaction を明示する。

- [ ] [ref] 外部公開を意図しない型の `public` / `internal` 境界を整理する。
  - CLI ツール単一アセンブリ内で使う Infra / Csv / Sqlite / Domain service に `public` な型やメンバーが多く、外部互換性を維持すべき API と内部実装の境界が読み取りづらい。
  - `InternalsVisibleTo` があるため、テスト目的だけで `public` にする必要は薄い。
  - 方針案: 利用者向けに公開する contract と内部実装を棚卸しし、不要な `public` は `internal` へ寄せる。

- [ ] [ref] `SettingsCache` の lifetime を整理する。
  - 設定変更後の再読み込みやテスト間の分離が分かりづらい。
  - 方針案: immutable settings snapshot を DI で渡す。

- [ ] [ref] CSV repository の `EnsureAvailable` 契約を明確にする。
  - availability check、ディレクトリ作成、ファイル作成の境界が曖昧。
  - 方針案: check と create を別メソッドにする。

- [ ] [ref] action label parsing と永続化 codec の責務を分ける。
  - `EntityValueCodec.ParseAction` が Palo Alto の日本語 action ラベルと永続化済み enum 名の両方を扱っている。
  - 同じ codec が Palo Alto import、SQLite 復元、Atomic CSV 復元で使われるため、vendor adapter の入力正規化と内部永続化形式の境界が曖昧。
  - `EntityValueCodec` という名前も、action label、policy index、JSON 省略キー serialization をまとめており責務範囲が広い。
  - 方針案: Palo Alto action label mapper、Domain action canonical codec、JSON value serializer を分ける。

- [ ] [bug] Atomic CSV の空 `group_id` を round-trip できない。
  - Domain / merge では空 `GroupId` を有効な識別子として扱い、Palo Alto import でも `|` がない場合は空文字列になる。
  - `CsvAtomicPolicyRepository` の読み取りは `group_id` に `GetRequiredValue` を使うため、export された atomic CSV に空 `group_id` があると再読込時に欠損扱いになる。
  - 方針案: 「列が存在しない」と「空文字列が有効」を分ける CSV helper を用意し、空値許容列を明示する。

- [ ] [ref] `SecurityPolicyTester` / `SecurityPolicyTestRunner` の名前と結果モデルを整理する。
  - `SecurityPolicyTester.Test` は実際には atomic 1 件が最初に含まれる merged を探す片方向 containment check であり、`test` コマンド全体の意味より狭い。
  - 内側の `SecurityPolicyTester.TestResult` が外側の `SecurityPolicyTestRunner.FindingKind` に依存しており、責務の向きが読み取りづらい。
  - 方針案: `MergedPolicyCoverageChecker` など照合内容を表す名前へ寄せ、finding/result の value object を runner から独立させる。

- [ ] [test] `merge` / `test` の大規模 partition 性能を測定する。
  - containment 判定や group compaction が入力サイズに対してどの程度伸びるか不明。
  - 方針案: benchmark または synthetic test を追加する。

- [ ] [spec] ポートを持たないプロトコルのサービス条件モデルを整理する。
  - `ServiceValue` は常に protocol / source port / destination port の 3 軸を持つため、ICMP などポート概念がないプロトコルも `icmp any any` のようなポート付き条件として扱われる。
  - merge / test の包含判定も全プロトコルでポート範囲を比較するため、意味を持たないポート軸が統合可否や差分判定へ混入する可能性がある。
  - `SmallWellKnownDestinationPortMatcher` も protocol / `Kind` を見ず destination port だけで判定するため、well-known port 例外の適用対象もこのモデル整理と合わせて決めたい。
  - 方針案: portful service condition、portless IP protocol condition、必要なら ICMP type/code condition を分ける。

- [ ] [spec] service protocol `255` の sentinel 用途と実データ用途を分ける。
  - `ServiceValueParser` は `Kind` 指定を protocol `255` / port `0` の番兵値で表す一方、直指定サービスの数値 protocol `255` も通常値として作れてしまう。
  - service 参照そのものの `any` は `0-255`、名前付きサービス定義や直指定の `any` は `0-254` に寄るため、`255` の意味が入口によって変わる。
  - 方針案: `Kind` 指定を数値サービス条件とは別 union case として持つか、IP protocol `255` の扱いを仕様として明示する。

- [ ] [ref] テスト名・コメントに残った旧称と文字化けを掃除する。
  - App 層は `UseCase` 命名へ寄っているが、テスト ファイル名に `*CommandActionTests.cs` / `*CommandActionProgressTests.cs` が残っている。
  - `PrecomputedAddressGroupCompactorTests.cs` も現行クラス名 `AddressGroupCompactorTests` とずれている。
  - `SecurityPolicyMergerTests` に文字化けしたコメントが残っており、意図が読めない。
  - 方針案: ファイル名とコメントを現行の用語へ揃え、履歴上の旧称をなくす。

## TODO 整理メモ

- `service any / Kind`、`Palo Alto の Service 列モデル分離`、`未定義サービス参照を Kind として許容する決定` は近いが、重複ではない。未定義参照を拒否するかどうかは決定済みで、残課題は解決後モデルの境界と包含意味の整理に絞る。
- `GroupId` の必須化は対応しない決定済みだが、`GroupId` という名前が表す用途の整理は別課題として残す。
- `wkpthreshold = 0` は許容する決定済みで、残課題は `wkport = 0` の親切エラーに限定する。
- `test` の双方向検証 / first-hit equivalence と、`merged` の canonical order 整理は近いが重複ではない。前者は検証モデル、後者は repository / export / test 間の順序契約を扱う。
- Domain runner の責務整理と logger 依存の整理は近いが重複ではない。前者は batch orchestration の所在、後者は診断出力の層依存を扱う。
- metadata の課題は現行コードでは `IToolMetadataRepository` に限定する。旧称の `IImportMetadataRepository` / `IAppMetadataRepository` は現存しないため TODO から外した。
- `merged export のアドレスグループ再利用任意化` と `AddressGroupCompactor の候補生成整理` は近いが重複ではない。前者は export の利用者向け出力方針、後者は compaction algorithm と候補入力の整合性を扱う。
- `merged export の service object / service group 名復元方針` は、`Palo Alto の Service 列モデル分離` と近いが重複ではない。前者は出力時の表示・復元方針、後者は入力表現と解決後条件の境界を扱う。
- `AddressGroupCompactor` の group 名衝突問題は、`import 入力検証` の object / group 名衝突検出で最終的に解消できる可能性がある。ただし現行コードでは compactor 固有の誤解決として表面化するため、compaction 側の候補生成整理にも残す。
- 外部公開境界の整理は、層依存や `GlobalUsings` の話と近いが重複ではない。前者は API surface / 互換性 / ドキュメント対象、後者は参照しやすさと namespace 可視性を扱う。
- action label parsing と codec 分離は、未定義 enum 値検証とは重複しない。前者は正規化・永続化形式の責務境界、後者は値域検証を扱う。
- `merged の traceability を exact source set で保持する` は現行結論のままでよい。将来 action range overlap の誤検知削減が必要になった場合は、traceability ではなく overlap 判定精度の課題として切り出す。

## 対応を見送る事項 (無期ペンディング)

- [ ] [req] Palo Alto ルール条件の未取込列を扱う。
  - `Source User` / `HIP Profiles` / `Url Category` が import 時に読み捨てられている。
  - いずれかに非空値が入ると、元ルールより広い条件として export されるおそれがある。
  - 方針案: まずは Domain にフィールドを追加して保持するか、未対応条件として import を拒否する。
  - 理由: Palo Alto 特有の機能により複雑化するのはこのツールの目標から外れる。他製品でもできる基本的なルールに関しての整理を目指している。

- [ ] [req] Allow 統合が異なる action の順序境界を越えないようにする。
  - 現在の merge は Allow のみを対象にしつつ、Deny などの非 Allow ルールを除外した順序でグループ化している。
  - 実機の first-hit semantics では、Deny を挟んだ前後の Allow をまとめると動作が変わる可能性がある。
  - 方針案: action が異なるルールを merge partition の境界として扱う。
  - 理由: 単純に merge partition 分割してしまうと、本来は集約可能であるにもかかわらず集約されなくなる。partition 分割による強制回避は見送る。現行は衝突検出で扱う。
  - 補足: 将来的にコマンドライン オプションで指定できるようする TODO を別に記載した。

## 対応しないと決定した事項

- [x] [spec] `GroupId` の扱いを堅くする
  - 現在は `ルールの使用状況 内容` の `|` より前を使い、取得できない場合は空文字列になります。
  - 空文字列に寄ると、本来別の整理単位にしたいルールが同じ `GroupId` として扱われる可能性があります。
  - 方針案: `GroupId` 必須モード、明示的な group 無視モード、列形式検証を追加する。
  - 結論: この挙動は意図的な仕様です。

- [x] [ux] merged の traceability を exact source set で保持する
  - 現在は `MinimumIndex` / `MaximumIndex` と `OriginalPolicyNames` が中心です。
  - 間に別 action があると action overlap warning が過検知になり、CSV から正確な元 index 集合を復元しにくいです。
  - 方針案: `OriginalPolicyIndices` の集合を持つ。
  - 結論: インデックス値は衝突チェックのためであり、トレーサビリティ情報ではありません。トレース情報はポリシー名で十分です。

- [x] [ux] export 時に既存 address object 名を復元する
  - address group compaction はありますが、単体 address object 名の復元はありません。
  - 実務レビューでは raw IP / CIDR より既存オブジェクト名のほうが扱いやすいです。
  - 結論: アドレス分解などに起因として、中途半端な対応となりえます。エクスポートしたCSVに基づいてアドレスオブジェクトを利用者が手動で再整理したほうがよいです。

- [x] [ux] merged export の service object / service group 名復元方針を整理する。
  - import では service object / service group を読み取るが、atomize 後は `ServiceValue` または `Kind` だけが主表現になり、merged CSV では直接指定サービス表記へ戻る。
  - address group だけ既存 group 名を再利用するため、address と service の出力方針が非対称になっている。
  - 方針案: service condition set と表示用 service object / group compaction を分け、復元する場合の安全条件を定義する。
  - 結論: 分解に起因として、本ツールでは中途半端な対応となりえます。エクスポートしたCSVに基づいて利用者が手動で再整理したほうがよいです。また、サービス グループを戻さないのは、製品仕様とします。

- [x] [ux] `wkpthreshold = 0` を拒否する値検証がない。
  - `wkpthreshold = 0` が通り、実質的に制御が無効化されます。
  - 結論: `wkpthreshold = 0` は、制御をスキップしたいときのためにむしろ必要。
  - 補足: `wkport = 0` の親切エラーは低優先度 TODO として別に扱う。

- [x] [spec] 未定義サービス参照を `Kind` として通してしまう。
  - `ServiceReferenceResolver` は service object / group / 3 要素直指定として解決できなかった文字列を `ResolvedService.Kind` に載せる。
  - `tcp hoge 80` や `ANY` のような入力ミスも atomize skip ではなく特殊サービス条件として残り、merge / export まで到達できる。
  - address 未定義参照は後段の parse error でスキップされる一方、service 未定義参照は通るため、入力不備の検出モデルが条件軸ごとに違う。
  - 方針案: `application-default` など許容する Palo Alto 特殊値を明示し、未定義 service 名 / 直指定形式エラー / 既知 Kind を別結果として扱う。
  - 結論: Palo Alto に特化した対応ではなく、他製品も視野に入れた柔軟性として、現状のままとする。

- [x] [spec] `merge` の単軸統合パスを固定点として扱うか整理する。
  - 現在は service -> source address -> destination address -> high similarity の一方向で実行し、後段で前段の統合機会が新しく生まれても戻らない。
  - destination address 統合後に service だけが異なる候補同士など、意味上はさらに統合できるルールが残る可能性がある。
  - 統合結果がパス順に依存し、どこまで最小化する処理なのか仕様から読み取りづらい。
  - 方針案: fixed-point まで繰り返すか、意図的なヒューリスティックとしてパス順と再評価しない範囲を仕様・テストで固定する。
  - 結論: 論理的に「destination address 統合後に service だけが異なる候補同士など、意味上はさらに統合できるルールが残る可能性」というものはありえない。そのため、残差再評価の話と完全に重複する。

- [x] [ref] `AtomicMergeCandidateDeduplicator` の名前を実処理に合わせる。
  - 実際には完全重複だけでなく、包含される Allow 候補を取り除いてトレース情報を生存側へ吸収している。
  - 方針案: `AtomicMergeCandidatePruner` / `ContainedAllowCandidateReducer` など、containment pruning を表す名前へ寄せる。
  - 結論: 現在の名前で問題ない。

## 対応済み事項

### 高優先度だったもの

- [x] [spec] 予約語 `any` とユーザー定義名の優先順位・大文字小文字規約を整理する。
  - address / service resolver は小文字 `any` を名前付き object / group より先に組み込み値として扱うため、同名 object / group は参照できない。
  - `ANY` は address では未解決値として後段エラーになり、service 参照では `Kind` になり、サービス定義内の port `ANY` は `any` として正規化され、application containment では case-insensitive に扱われる。
  - 対応内容: 「名前が混在しうる箇所は case-sensitive、値だけの軸は必要に応じて内部処理用に正規化する」旨、仕様として明記した。
  - 補足: address object の値に `any` は存在しない前提とし、service 定義 protocol の `ANY` は許可しない。

- [x] [spec] application 値を正規化する。
  - application の `any` / 大文字小文字差分を Domain value object として正規化するか決める。
  - 対応内容: 「application 値は製品・環境ごとの識別子として入力表記を保持し、正規化しない。」旨、仕様として明記した。
  - 補足: `any` の特別扱いは containment 判定など必要な箇所に限定し、保存値や表示値は勝手に書き換えない。

- [x] [spec] application 値の統合方針を整理する。
  - merge は application 差分をまたいで統合しないため、サービス統合後もルールが残るケースがある。
  - 対応内容: 「application は製品・環境ごとの意味を持つ条件軸として扱い、異なる application 値をまたいだ統合対象にはしない。」旨、仕様として明記した。
  - 補足: `any` が個別 application を包含する判定は shadow / containment のために使うが、merged rule の application 集合を広げる目的では使わない。
