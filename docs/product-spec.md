# FirewallRuleToolkit 製品仕様書

- [1. 製品概要](#1-製品概要)
- [2. 対象ユーザーと利用シーン](#2-対象ユーザーと利用シーン)
- [3. 対象範囲](#3-対象範囲)
  - [3.1. サポート対象](#31-サポート対象)
  - [3.2. 対象外](#32-対象外)
- [4. システム構成](#4-システム構成)
- [5. 基本処理フロー](#5-基本処理フロー)
- [6. 共通仕様](#6-共通仕様)
  - [6.1. 共通オプション](#61-共通オプション)
  - [6.2. 設定の解決順](#62-設定の解決順)
  - [6.3. 終了コード](#63-終了コード)
  - [6.4. ログ](#64-ログ)
  - [6.5. 名前・予約語・大文字小文字](#65-名前予約語大文字小文字)
- [7. 機能仕様](#7-機能仕様)
  - [7.1. `import`](#71-import)
    - [7.1.1. 目的](#711-目的)
    - [7.1.2. 入力](#712-入力)
    - [7.1.3. 入力 CSV の前提](#713-入力-csv-の前提)
    - [7.1.4. 取り込み時の正規化](#714-取り込み時の正規化)
    - [7.1.5. 永続化動作](#715-永続化動作)
  - [7.2. `atomize`](#72-atomize)
    - [7.2.1. 目的](#721-目的)
    - [7.2.2. 前提](#722-前提)
    - [7.2.3. 解決ルール](#723-解決ルール)
    - [7.2.4. 範囲展開ルール](#724-範囲展開ルール)
    - [7.2.5. エラー時の扱い](#725-エラー時の扱い)
    - [7.2.6. 出力](#726-出力)
  - [7.3. `merge`](#73-merge)
    - [7.3.1. 目的](#731-目的)
    - [7.3.2. 前提](#732-前提)
    - [7.3.3. パーティション](#733-パーティション)
    - [7.3.4. shadow 判定](#734-shadow-判定)
    - [7.3.5. Allow ルールの統合](#735-allow-ルールの統合)
    - [7.3.6. 非 Allow ルールの統合](#736-非-allow-ルールの統合)
    - [7.3.7. well-known port 例外](#737-well-known-port-例外)
    - [7.3.8. 重複検知](#738-重複検知)
    - [7.3.9. 出力](#739-出力)
  - [7.4. `export`](#74-export)
    - [7.4.1. 目的](#741-目的)
    - [7.4.2. 入力](#742-入力)
    - [7.4.3. 前提](#743-前提)
    - [7.4.4. 出力仕様](#744-出力仕様)
    - [7.4.5. 出力ヘッダー](#745-出力ヘッダー)
  - [7.5. `test`](#75-test)
    - [7.5.1. 目的](#751-目的)
    - [7.5.2. 前提](#752-前提)
    - [7.5.3. 比較対象](#753-比較対象)
    - [7.5.4. 走査順](#754-走査順)
    - [7.5.5. 含有判定](#755-含有判定)
    - [7.5.6. 判定結果の扱い](#756-判定結果の扱い)
    - [7.5.7. 出力](#757-出力)
  - [7.6. `stat`](#76-stat)
    - [7.6.1. 目的](#761-目的)
    - [7.6.2. 表示内容](#762-表示内容)
    - [7.6.3. 表示ルール](#763-表示ルール)
- [8. 入力データ仕様](#8-入力データ仕様)
  - [8.1. セキュリティ ポリシー CSV](#81-セキュリティ-ポリシー-csv)
  - [8.2. アドレス関連](#82-アドレス関連)
  - [8.3. サービス関連](#83-サービス関連)
- [9. エラー処理と利用制約](#9-エラー処理と利用制約)
- [10. 非機能仕様](#10-非機能仕様)
- [11. 典型実行例](#11-典型実行例)
- [12. 関連資料](#12-関連資料)

## 1. 製品概要

FirewallRuleToolkit は、Palo Alto Networks 形式の CSV を読み込み、ファイアウォール ルールを段階的に整理する CLI ツールです。  
主な目的は、ルールベースを作業用 DB へ取り込み、ルールを atomic 単位へ分解し、その結果を条件単位で再統合し、最終的に CSV として再出力できるようにすることです。

本製品は、次の 6 つのユースケースを提供します。

| コマンド | 役割 | 主な入出力 |
| --- | --- | --- |
| `import` | Palo Alto CSV を作業用 DB へ取り込む | 入力 CSV -> SQLite |
| `atomize` | ルールを原子的な単位へ展開する | Imported -> Atomic |
| `merge` | atomic 化したルールを統合する | Atomic -> Merged |
| `test` | merge 結果が shadowed 除去後 atomic と矛盾しないか検査する | Atomic + Merged -> ログ |
| `export` | atomic / merged を CSV 出力する | SQLite -> CSV |
| `stat` | DB の処理段階と件数を確認する | SQLite -> 標準出力 |

## 2. 対象ユーザーと利用シーン

- Palo Alto のルールベースを棚卸ししたい運用担当者
- ルール粒度を細分化して影響範囲を分析したい設計担当者
- 重複や類似条件を整理したうえで移行用 CSV を作りたい担当者
- バッチ処理で import -> atomize -> merge -> export を順に回したい利用者

## 3. 対象範囲

### 3.1. サポート対象

- 実行形態は Windows 上の CLI
- 入力形式は Palo Alto Networks 形式の CSV
- 永続化ストアは SQLite
- 対応する主な処理対象は IPv4 アドレス、IPv4 CIDR、IPv4 範囲、サービス定義、サービス グループ、アドレス グループ

### 3.2. 対象外

- GUI
- Palo Alto 以外のベンダー固有 CSV
- 機器への直接接続や API 連携
- IPv6
- Event Log へのログ出力

`--logtype EventLog` は列挙値として存在しますが、現時点では未実装です。

## 4. システム構成

本製品は、CLI 層、App 層、Domain 層、Infra 層で構成されます。

- CLI 層は `System.CommandLine` によりサブコマンドとオプションを受け付ける
- App 層は各コマンドの実行構成と前提チェックを担当する
- Domain 層はアドレス解決、サービス解決、atomic 化、merge などの業務ロジックを担当する
- Infra 層は CSV と SQLite の入出力を担当する

CLI / App 層は、具象 Infra の生成を Composition に閉じ込めます。実際の読み書き操作は Domain 層で定義した Port 経由で行います。

主な Port は次のとおりです。

| Port | 用途 |
| --- | --- |
| `IReadRepository<T>` | エンティティ列挙 |
| `IWriteRepository<T>` | 初期化、追記、全件置換 |
| `IReadWriteRepository<T>` | 読み書き兼用 repository |
| `IItemCountRepository` | 全件復元を伴わない件数取得 |
| `IWriteRepositorySession` | 複数 repository への書き込みを 1 トランザクションへ束ねる |
| `IWriteRepositorySessionFactory` | 書き込みセッションの開始 |

作業用 DB は、`--database` で指定したディレクトリ配下の単一 SQLite ファイルとして保存されます。

| ファイル | 内容 |
| --- | --- |
| `database.sqlite` | import 済みデータ、atomize 結果、merge 結果 |

`import` / `atomize` / `merge` は `IWriteRepositorySession` を使い、コマンド単位の SQLite トランザクション内で対象テーブルを再生成します。途中で中断または失敗した場合、未完了の書き込みはロールバックされます。`export` はテンポラリ CSV を作成してから置き換えます。

## 5. 基本処理フロー

標準的な実行順は次のとおりです。

1. `import`
2. `atomize`
3. `merge`
4. `test`
5. `export`
6. `stat`

各段階の前提は次のとおりです。

| コマンド | 実行前提 |
| --- | --- |
| `import` | なし |
| `atomize` | `import` 済み |
| `merge` | `atomize` 済み |
| `test` | `atomize` 済みかつ `merge` 済み |
| `export` | `Atomic` 出力は `atomize` 済み、`Merged` 出力は `merge` 済み |
| `stat` | なし |

## 6. 共通仕様

### 6.1. 共通オプション

| オプション | 内容 |
| --- | --- |
| `--config` | 設定 JSON のパス。未指定時は `fwrule-tool.json` |
| `--database` | 作業用 SQLite ディレクトリ |
| `--logtype` | `ConsoleOnly` または `File` |
| `--logfile` | `File` ログの出力先 |
| `--loglevel` | 最小ログ レベル |

### 6.2. 設定の解決順

- コマンドラインで指定した値を優先する
- コマンドライン未指定の値は `--config` で指定した JSON から補う
- `--config` 未指定時はカレント ディレクトリの `fwrule-tool.json` を参照する

### 6.3. 終了コード

- 正常終了時は `0`
- 引数不備、前提未達、未処理例外時は `1`

### 6.4. ログ

- 既定はコンソール出力
- `File` 指定時はファイルへも出力する
- 例外は直接標準出力へ書かず、ロガー経由で扱う
- `atomize` は 200 件ごとの入力ポリシー処理で進捗を出す
- `merge` は 2000 件ごとの atomic 処理で進捗を出す

### 6.5. 名前・予約語・大文字小文字

object 名、group 名、Kind 指定、application 値など、ユーザー定義名や製品固有名が混在しうる値は case-sensitive に扱います。
値だけを表す入力軸では、取り込み時または解決時に内部処理用の alias 正規化を行う場合があります。

予約語 `any` の扱いは次のとおりです。

- ポリシーのアドレス参照欄とサービス参照欄では、小文字 `any` だけを予約語として扱う
- 小文字 `any` は、同名の object / group より先に組み込み値として解決するため、小文字 `any` という address / service object または group は参照できない
- `ANY` など大文字小文字が異なる値は予約語として扱わず、完全一致する object / group 名があればそれを解決対象とする
- 完全一致する object / group がないアドレス参照 `ANY` は、後続のアドレス値解析で不正値として扱われうる
- 完全一致する object / group がないサービス参照 `ANY` は、Kind 指定として扱う

アドレス関連の `any` は次のとおりです。

- address object の値に `any` は存在しない前提とし、address object の値は IPv4 単一アドレス、CIDR、IPv4 範囲だけを扱う
- ポリシーのアドレス参照欄の小文字 `any` は、解決後に `0.0.0.0/0` として扱う

サービス関連の `any` は次のとおりです。

- サービス参照そのものの小文字 `any` は、全サービスを表す組み込み値として扱う
- 直指定サービス `<protocol> <source-port> <destination-port>` の各軸に現れる `any` は小文字のみを特別扱いする
- `TCP ANY 80` のように直指定サービスの軸値で大文字小文字が異なる `any` は直指定として扱わず、サービス参照全体を Kind 指定として扱う
- 名前付きサービス定義の source port / destination port は、Palo Alto CSV 取り込み時に内部処理用として `any` / `ANY` を `1-65535` へ正規化する
- 名前付きサービス定義の protocol alias `tcp` `udp` `icmp` `sctp` は小文字のみを IP プロトコル番号へ正規化する
- 名前付きサービス定義または直指定サービスの protocol 軸に現れる `any` は小文字のみを特別扱いし、`ANY` は許可しない

application 値は入力表記を保持し、取り込み時に `any` や大文字小文字差分を正規化しません。
通常の application 値比較は case-sensitive とし、containment / shadow 判定で包含側が `any` の場合だけ大文字小文字を区別せず個別 application を包含するとみなします。

## 7. 機能仕様

### 7.1. `import`

#### 7.1.1. 目的

Palo Alto 形式の CSV を読み取り、後続処理の起点となる作業用 DB を構築します。

#### 7.1.2. 入力

- セキュリティ ポリシー CSV
- アドレス オブジェクト CSV
- アドレス グループ CSV
- サービス オブジェクト CSV
- サービス グループ CSV

#### 7.1.3. 入力 CSV の前提

- 区切り文字はカンマ
- マルチ値フィールドは `;` 区切り
- 文字コードは `--encoding` で指定する
- UTF-8 BOM 付き入力は `--withbom` で扱う

#### 7.1.4. 取り込み時の正規化

- 名前付きアドレス定義の単一 IPv4 は `/32` へ正規化する
- セキュリティ ポリシーのアドレス参照欄の小文字 `any` は、後続解決で `0.0.0.0/0` として扱う
- 名前付きサービス定義の `TCP` `UDP` `ICMP` `SCTP` は、大文字小文字を区別せず IP プロトコル番号へ正規化する
- 名前付きサービス定義の source port / destination port の `any` は、大文字小文字を区別せずポート範囲 `1-65535` へ正規化する
- `0-xxxx` 形式のポート範囲は `1-xxxx` へ補正する
- セキュリティ ポリシーのアプリケーション値は入力表記を保持し、`any` や大文字小文字差分を取り込み時に正規化しない
- セキュリティ ポリシーの `ルールの使用状況 内容` に `AAA|BBB` 形式がある場合、`AAA` を `group_id` として採用する

#### 7.1.5. 永続化動作

- 定義 / グループ系テーブルと imported policy テーブルを同一トランザクション内で全件置換する
- imported policy はポリシー名を主キーとし、ポリシー インデックスは順序情報として一意制約を持つ
- `import` 実行前の既存 imported データは Commit 時に上書きされる
- `import` が途中で失敗した場合、未確定の書き込みはロールバックされる

### 7.2. `atomize`

#### 7.2.1. 目的

import 済みポリシーを、送信元ゾーン、送信元アドレス、宛先ゾーン、宛先アドレス、アプリケーション、サービスの 1 組み合わせ 1 件へ展開します。

#### 7.2.2. 前提

- `import` が完了していること
- `threshold` が 1 以上であること

#### 7.2.3. 解決ルール

- アドレス参照は小文字 `any`、名前付きアドレス定義、アドレス グループ、直接値の順に解決対象とする
- サービス参照は小文字 `any`、名前付きサービス定義、サービス グループ、直指定、Kind 指定 (`application-default` など) の順に解決対象とする
- サービス参照そのものの `any` は、ServiceValue 上ではプロトコル `0-255`、送信元ポート `0-65535`、宛先ポート `0-65535`、`Kind = null` として扱う
- 名前付きサービス定義または直指定サービスの各軸に現れる小文字 `any` は、プロトコルでは `0-254`、ポートでは `1-65535` として扱う
- サービス参照欄の `ANY` は組み込み `any` ではなく、完全一致するサービス定義 / サービス グループがなければ Kind 指定として扱う
- プロトコル範囲の終端 `255` は `254` へ補正し、ポート範囲の開始 `0` は `1` へ補正する。カンマ区切り複数値では各要素ごとに補正する
- グループの再帰参照を検知した場合は当該ポリシーをスキップする

#### 7.2.4. 範囲展開ルール

- アドレスのハイフン範囲、プロトコル範囲、ポート範囲は、要素数が `threshold` 未満のときだけ単一値へ分解する
- CIDR は `threshold` による単一 IP への分解対象外とし、atomic 化後も 1 つのアドレス範囲値として保持する
- 要素数が `threshold` 以上の範囲は範囲のまま保持する
- atomic 化はアクション種別に関係なく実施する

#### 7.2.5. エラー時の扱い

- ポリシー 1 件の解決中に `FormatException` または `InvalidOperationException` が発生した場合、そのポリシーのみスキップして継続する
- スキップ時は警告ログへポリシー名、元インデックス、理由を記録する
- 出力側の書き込み失敗など、処理基盤側の例外は中断する

#### 7.2.6. 出力

`atomic_security_policies` を再生成します。既存内容は毎回作り直します。
再生成は SQLite トランザクション内で行い、処理基盤側の例外で中断した場合は未確定の atomic 結果をロールバックします。

### 7.3. `merge`

#### 7.3.1. 目的

atomic 化済みルールを、意味を保ちつつ条件単位で再統合し、`merged_security_policies` を生成します。

#### 7.3.2. 前提

- `atomize` が完了していること

#### 7.3.3. パーティション

merge は少なくとも次の単位でパーティション分割して処理します。

- `FromZone`
- `ToZone`
- `Service.Kind`

merge に渡す atomic は、`FromZone`、`ToZone`、`Service.Kind`、`OriginalIndex`、保存順の順で整列されているものとします。
同じ merge パーティションに属する atomic は連続していなければなりません。Domain の merge runner は入力列を並び替えず、順序契約違反も検出しません。SQLite 実装の `GetAllOrderedForMerge()` はこの順序で atomic を提供します。

#### 7.3.4. shadow 判定

- 同一パーティション内で、先行ルールが後続ルールのアプリケーション、送信元アドレス、宛先アドレス、サービスを完全包含する場合、後続ルールは shadowed とみなす
- アプリケーションの shadow 判定では、先行ルールのアプリケーションが `any` の場合、後続ルールの個別アプリケーションを shadow するとみなす
- shadowed な後続ルールは出力対象から外す
- ただし、元インデックス範囲と元ポリシー名は生存側へ吸収する
- shadow 判定はアクション差異があっても適用される

#### 7.3.5. Allow ルールの統合

Allow ルールは次の順で統合します。

1. 完全に包含するルールを統合
2. サービスのみが異なるルールを統合
3. 送信元アドレスのみが異なるルールを統合
4. 宛先アドレスのみが異なるルールを統合
5. 高一致率な 2 ルールを共通部と残差へ再編成

application は統合対象の差分軸に含めません。異なる application 値を持つルールは、`any` が個別 application を包含する場合でも、application 差分をまたいで 1 件へ統合しません。

完全包含ルールの条件は次のとおりです。

- 対象は同一 merge パーティション内の Allow 候補同士とする
- 比較対象どうしで `FromZone` `ToZone` `Action` `GroupId` が一致すること
- 包含側の `SourceAddress` が被包含側の `SourceAddress` を包含すること
- 包含側の `DestinationAddress` が被包含側の `DestinationAddress` を包含すること
- 包含側の `Application` が被包含側の `Application` を包含すること
  - アプリケーションの包含判定では、`any` は個別アプリケーションを包含する
- 包含側の `Service` が被包含側の `Service` を包含すること
  - サービスの包含判定では、プロトコル範囲、送信元ポート範囲、宛先ポート範囲が被包含側を覆い、`Kind` が一致していることを条件とする

高一致率再編成の条件は次のとおりです。

- 類似度しきい値は config JSON または `--hspercent` で必ず指定する
- 比較対象は同じ `FromZone` `ToZone` `Application` `Action` `GroupId` を持つ候補群
- 宛先アドレス集合の共通部分が左右それぞれ `hspercent` % 以上
- サービス集合の共通部分が左右それぞれ `hspercent` % 以上
- 条件を満たすペアのうち、共通宛先数と共通サービス数の合計が最大のペアから順に再編成する

再編成時の出力ルールは次のとおりです。

- 共通部は送信元 Union、共通宛先、共通サービスで 1 件作る
- 残差は各候補の元の送信元を保ちつつ、宛先差分とサービス差分で作る
- 共通部は次の比較対象として再利用する

#### 7.3.6. 非 Allow ルールの統合

- `Deny` `Drop` `ResetBoth` などの非 Allow は、同じ元ルール由来の atomic だけを束ねる
- 異なる元インデックスの非 Allow 同士は統合しない
- shadowed 除去で元インデックス範囲や元ポリシー名を吸収した結果、同じ元ルール由来の非 Allow が複数の merged に分断される場合がある
- 上記の分断は仕様として許容し、shadowed 除去後に再統合しない

#### 7.3.7. well-known port 例外

`--wkport` と `--wkpthreshold` を両方指定した場合、small well-known destination ports 制御を有効化します。

- `wkport` は個別ポートの列挙であり、範囲指定は不可
- すべての宛先ポートが `wkport` に含まれる
- 宛先ポート数が `wkpthreshold` 未満である
- すべてのサービスが単一宛先ポートである

上記を満たす場合に限り、宛先アドレス集約を抑止します。  
同じ条件は高一致率再編成でも使い、共通サービス集合が small well-known destination ports に該当するペアは再編成対象から外します。

#### 7.3.8. 重複検知

- merge 結果の元インデックス範囲が、異なるアクション同士で重複する場合は警告ログへ出力する
- 詳細ログは重複した各組み合わせごとに表示する

#### 7.3.9. 出力

`merged_security_policies` を再生成します。既存内容は毎回作り直します。
再生成は SQLite トランザクション内で行い、途中で中断した場合は未確定の merged 結果をロールバックします。

### 7.4. `export`

#### 7.4.1. 目的

作業用 DB に保存された atomic または merged の結果を CSV へ書き出します。

#### 7.4.2. 入力

- `--target` は `Atomic` `Merged` または両方
- `Atomic` を含む場合は `--atomic` が必須
- `Merged` を含む場合は `--merged` が必須

#### 7.4.3. 前提

- `Atomic` 出力には `atomize` 済みデータが必要
- `Merged` 出力には `merge` 済みデータが必要

#### 7.4.4. 出力仕様

- 文字コードは `--encoding` で指定する
- UTF-8 BOM 付き出力は `--withbom` で有効化する
- merged CSV は人が読みやすい表現で出力する
- merged CSV のアドレスは CIDR 化できる範囲を CIDR 表記へ戻す
- merged CSV の `any` 相当範囲は `any` と出力する
- merged CSV のサービス参照 `any` 相当 (`0-255 0-65535 0-65535`) は `any` と出力する
- merged CSV の 3 軸指定サービスは `tcp any 80-90` のような可読形式で出力する。各軸がすべて `any` 相当の場合は `any any any` と出力し、サービス参照 `any` とは区別する
- import 済みのアドレス グループ情報が利用可能な場合、merged 出力では既存グループ名へ圧縮して再利用する

#### 7.4.5. 出力ヘッダー

Atomic 出力ヘッダー:

- `from_zone`
- `source_address_json`
- `to_zone`
- `destination_address_json`
- `application`
- `service_json`
- `action`
- `group_id`
- `original_index`
- `original_policy_name`

Merged 出力ヘッダー:

- `from_zones`
- `source_addresses`
- `to_zones`
- `destination_addresses`
- `applications`
- `services`
- `action`
- `group_id`
- `minimum_index`
- `maximum_index`
- `original_policy_names`

### 7.5. `test`

#### 7.5.1. 目的

`merge` 結果が、`merge` 前処理で shadowed 除去後に残る atomic の挙動を保持しているかを検査します。

検査結果はログへ出力し、DB の内容は変更しません。

#### 7.5.2. 前提

- `atomize` が完了していること
- `merge` が完了していること

#### 7.5.3. 比較対象

- 検査対象の atomic は、`atomic_security_policies` 全件そのものではなく、`merge` の shadow 判定と同じ定義で shadowed 除去した後に残る atomic とする
- shadowed 判定は `merge` の仕様と同一とし、同一パーティション内で先行ルールが後続ルールのアプリケーション、送信元アドレス、宛先アドレス、サービスを完全包含する場合に後続ルールを shadowed とみなす
- shadowed に落ちた atomic も別枠で確認対象に含める
- `merged_security_policies` は `merge` 済みの内容をそのまま比較対象とする

#### 7.5.4. 走査順

- atomic は `OriginalIndex` の昇順で走査する
- atomic は第 2 キーを規定しない
- merged は `MinimumIndex` の昇順、同値時は `MaximumIndex` の昇順で走査する
- `MinimumIndex` と `MaximumIndex` の両方が同値である merged 同士の最終順は規定しない

#### 7.5.5. 含有判定

- 各 atomic について、ソート済み merged の先頭から順に「含まれる」 merged を探索する
- 複数の merged が条件を満たす場合は、最初にヒットした 1 件だけを採用する
- 「含まれる」の判定では `Action` を除外し、次の条件をすべて満たしたときに成立する
- `atomic.FromZone` が `merged.FromZones` に含まれる
- `atomic.ToZone` が `merged.ToZones` に含まれる
- `merged.Applications` のいずれかが `atomic.Application` を包含する
- `merged.SourceAddresses` のいずれかが `atomic.SourceAddress` を包含する
- `merged.DestinationAddresses` のいずれかが `atomic.DestinationAddress` を包含する
- `merged.Services` のいずれかが `atomic.Service` を包含する
- `GroupId` は比較対象外とする
- `OriginalIndex`、`MinimumIndex`、`MaximumIndex`、`OriginalPolicyName`、`OriginalPolicyNames` は比較対象外とする
- アプリケーション、アドレス、サービスは `merge` の包含判定と同じ基準で評価する

#### 7.5.6. 判定結果の扱い

- 含まれる merged が見つかり、その `Action` が atomic の `Action` と一致する場合は正常とみなし、特別なログは出さない
- 含まれる merged が見つかったが `Action` が一致しない場合、shadowed ではない atomic は warning として記録する
- 含まれる merged が見つからない場合、shadowed ではない atomic は warning として記録する
- shadowed に落ちた atomic で `Action` 不一致または未包含があった場合は informational として記録する
- shadowed の informational 記録はログ量が多くなる場合でも省略しない

#### 7.5.7. 出力

- `test` は DB のテーブルを更新しない
- 検査結果は logger 経由で出力する
- warning と informational のログは、atomic を特定できる情報を含める
- 最初にヒットした merged が存在する場合は、その merged を特定できる情報も含める
- `merge` サブコマンドと同じ頻度で進捗状況をログ出力する

### 7.6. `stat`

#### 7.6.1. 目的

現在の DB の処理段階と主要件数を素早く確認します。

#### 7.6.2. 表示内容

- Import の完了有無
- `security_policies`
- `address_objects`
- `address_group_members`
- `service_objects`
- `service_group_members`
- Atomize の完了有無
- `atomic_security_policies`
- Merge の完了有無
- `merged_security_policies`

#### 7.6.3. 表示ルール

- 未実行段階は `not imported` `not atomized` `not merged` と表示する
- 実行済み段階は `completed` と件数を表示する
- 件数取得は `IItemCountRepository` 経由で行う
- SQLite 実装では `SELECT COUNT(*)` を使い、全件列挙、JSON デシリアライズ、表示用の並び替えを行わない

## 8. 入力データ仕様

### 8.1. セキュリティ ポリシー CSV

主に次のヘッダーを使用します。

| ヘッダー | 用途 |
| --- | --- |
| 先頭列 | ルール インデックス |
| `名前` | ポリシー名 |
| `送信元 ゾーン` | `;` 区切りの送信元ゾーン |
| `送信元 アドレス` | `;` 区切りの送信元アドレス参照 |
| `宛先 ゾーン` | `;` 区切りの宛先ゾーン |
| `宛先 アドレス` | `;` 区切りの宛先アドレス参照 |
| `アプリケーション` | `;` 区切りのアプリケーション |
| `サービス` | `;` 区切りのサービス参照 |
| `アクション` | `Allow` / `Deny` / `Drop` / `ResetBoth` または対応する日本語表記 |
| `ルールの使用状況 内容` | `group_id` 抽出元 |

### 8.2. アドレス関連

- 単一 IPv4、CIDR、IPv4 範囲を扱う
- ポリシーのアドレス参照欄では小文字 `any` を扱う
- address object の値として `any` は扱わない
- IPv6 は扱わない

### 8.3. サービス関連

- 直指定サービスは `<protocol> <source-port> <destination-port>` の 3 要素で扱う
- プロトコル、送信元ポート、宛先ポートは単一値、範囲、カンマ区切り複数値を扱う
- 小文字 `any` を扱う
- サービス参照としての `any` と、3 要素の各軸に現れる `any` は区別して扱う
- 直指定として解釈できないサービス参照は Kind 指定として扱う
- `application-default` などの Kind 指定を特別なサービス種別として扱う

## 9. エラー処理と利用制約

- 前提未達時はコマンド エラーで終了する
- `merge` の well-known port 制御は `--wkport` と `--wkpthreshold` の同時指定が必須
- `merge` の `hspercent` は config JSON または `--hspercent` で指定が必要
- `wkport` に範囲指定はできない
- `threshold` は 1 以上でなければならない
- `hspercent` は 1 以上 100 以下でなければならない
- サービス値やアドレス値が解釈不能な場合、`atomize` では該当ポリシーをスキップすることがある
- 設定ファイルが読めない場合は警告ログを出し、設定未読込として処理する
- `--logtype File` で `--logfile` がない場合はエラーとなる

## 10. 非機能仕様

- サブコマンドは単体で実行できる CLI であること
- DB の中間成果物を再利用し、段階実行できること
- `import` / `atomize` / `merge` はコマンド単位の SQLite トランザクションで結果を確定し、未完了時はロールバックすること
- `stat` の件数取得は保存済みエンティティの全件復元を伴わないこと
- 例外はログ経由で記録し、異常終了時は終了コードで判定できること

## 11. 典型実行例

```powershell
fwrule-tool import `
  --database work-db `
  --securitypolicies .\input_securitypolicies.csv `
  --addresses .\input_addresses.csv `
  --addressgroups .\input_addressgroups.csv `
  --services .\input_services.csv `
  --servicegroups .\input_servicegroups.csv

fwrule-tool atomize --database work-db --threshold 25
fwrule-tool merge --database work-db --wkport 20,21,22,23,80,443,3389 --wkpthreshold 3 --hspercent 80
fwrule-tool test --database work-db
fwrule-tool export --database work-db --target Atomic,Merged --atomic .\atomic.csv --merged .\merged.csv
fwrule-tool stat --database work-db
```

## 12. 関連資料

- merge 実行シーケンス図: `docs/merge-runner-sequence.pu`
- 既存の merge マージャー図: `docs/merge-merger-sequence.pu`
- 利用者向け概要: `README.md`
