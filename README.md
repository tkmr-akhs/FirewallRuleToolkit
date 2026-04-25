# FirewallRuleToolkit

FirewallRuleToolkit は、Palo Alto Networks 形式の CSV を読み込み、
ファイアウォール ルールを段階的に整理・分解・統合・出力する CLI ツールです。

## このツールについて

このツールは、主に次の流れで利用します。

| 手順 | コマンド  | 役割                                          | 前提                                          | 主な出力                 |
| ---- | --------- | --------------------------------------------- | --------------------------------------------- | ------------------------ |
| 1    | `import`  | 各種 CSV を作業用 DB に取り込む               | なし                                          | import 済み DB           |
| 2    | `atomize` | ルールを原子的な単位へ展開する                | `import` 済み                                 | atomic_security_policies |
| 3    | `merge`   | atomic 化した結果を条件単位で統合する         | `atomize` 済み                                | merged_security_policies |
| 4    | `test`    | merge 結果が atomic の挙動を保っているか検査する | `atomize` 済みかつ `merge` 済み               | ログ                     |
| 5    | `export`  | atomic / merged 結果を CSV 出力する           | target に応じて `atomize` または `merge` 済み | 出力 CSV                 |
| 6    | `stat`    | DB の状態と件数を確認する                     | なし                                          | 標準出力                 |

## 基本的な使い方

### 1. import

```powershell
fwrule-tool import `
  --database work-db `
  --securitypolicies input_securitypolicies.csv `
  --addresses input_addresses.csv `
  --addressgroups input_addressgroups.csv `
  --services input_services.csv `
  --servicegroups input_servicegroups.csv
```

### 2. atomize

```powershell
fwrule-tool atomize --database work-db --threshold 25
```

`threshold` は、アドレス範囲やポート範囲を単一値へ分解するしきい値です。
要素数が `threshold` 未満なら単一値へ展開し、`threshold` 以上なら範囲のまま保持します。

### 3. merge

```powershell
fwrule-tool merge --database work-db --hspercent 80
```

`merge` は atomic 化済みルールを統合し、
Allow ルールは条件単位で再統合し、Allow 以外のルールは同じ元ルール由来の atomic だけを束ねます。
また、先行ルールが後続ルールを完全に覆う場合は、元インデックスが小さい側を優先します。
Allow ルールは、サービス集約 -> 送信元集約 -> 宛先集約の 3 パス後に、
宛先アドレスとサービスの各軸で 80% 以上一致する 2 ルールを、
送信元 Union を持つ共通部 1 件と、元の送信元を保つ残差へ再編成します。
高一致率再編成に使う `--hspercent` は必須です。
設定ファイルまたはコマンドラインのどちらかで指定してください。
既定の `fwrule-tool.json` を使う場合は `80` が設定済みです。
よく使う宛先ポートだけで構成された小さなポート集合について、宛先アドレスをまとめすぎたくない場合は、
`--wkport` と `--wkpthreshold` を併用します。

```powershell
fwrule-tool merge `
  --database work-db `
  --hspercent 80 `
  --wkport 20,21,22,23,80,443,3389 `
  --wkpthreshold 3
```

- `--wkport` は、よく使う宛先ポートの一覧です。
- `--wkpthreshold` は、宛先アドレス集約を抑止する閾値です。

宛先ポート数が `wkpthreshold` 未満であっても、`wkport` に含まれないポートが 1 つでもあれば、
宛先アドレス集約を行います。

宛先ポートがすべて `wkport` に含まれ、かつ、その個数が `wkpthreshold` 未満のときだけ、
宛先アドレス集約を行いません。

同じ条件は、3 パス後の高一致率再編成でも利用します。
共通サービス集合が small well-known destination ports に該当するペアは、そのペアだけ再編成をスキップします。

### 4. test

```powershell
fwrule-tool test --database work-db
```

`test` は、`merge` 結果が shadowed 除去後 atomic の挙動を保持しているかを検査します。
各 atomic について、ソート済み merged の先頭から順に含まれるものを探し、
見つからない場合や Action が異なる場合はログへ記録します。

- shadowed ではない atomic の不一致は `warning` です。
- shadowed に落ちた atomic の不一致は `informational` です。
- DB の内容は変更しません。

### 5. export

```powershell
fwrule-tool export `
  --database work-db `
  --target Atomic,Merged `
  --atomic output_atomic.csv `
  --merged output_merged.csv
```

- `Atomic` は `atomize` 結果を出力します。
- `Merged` は `merge` 結果を出力します。
- `Atomic,Merged` のように両方を指定できます。

### 6. stat

```powershell
fwrule-tool stat --database work-db
```

`stat` は import / atomize / merge がどこまで完了しているかと、
主要テーブル件数を表示します。

## グローバル オプション

次のオプションはすべてのサブコマンドで利用できます。

| オプション   | 説明                                                                         |
| ------------ | ---------------------------------------------------------------------------- |
| `--config`   | 設定ファイル JSON のパスです。未指定時は `fwrule-tool.json` を読み込みます。 |
| `--database` | 作業用 SQLite データベースを保存するフォルダーです。                         |
| `--logtype`  | ログ出力先です。通常は `ConsoleOnly` / `File` を使います。`EventLog` は未実装です。 |
| `--logfile`  | `logtype` が `File` のときのログ出力先です。`ConsoleOnly` では省略できます。 |
| `--loglevel` | 出力する最小ログ レベルです。調査時は `Debug` や `Trace` が便利です。        |

コマンドラインで未指定の値は、`--config` で指定した設定ファイルから読み込みます。

## サブコマンドごとの補足

### import

- 後続の `atomize` / `merge` / `test` / `export` / `stat` の起点になるコマンドです。
- セキュリティ ポリシー内のアドレス名・サービス名は、取り込み後に後続の `atomize` でオブジェクト / グループ定義を使って解決されます。
- 入力 CSV の文字コードは `--encoding` で指定します。
- UTF-8 BOM 付き CSV を読む場合は `--withbom` を指定します。
- `import` は単一の作業用 DB ファイルをトランザクションで更新します。途中で中断または失敗した場合、未完了の書き込みはロールバックされます。

### atomize

- import 済みポリシーを atomic 化します。
- 送信元 / 宛先アドレス、アプリケーション、サービスの組み合わせごとに展開されます。
- `Allow` / `Deny` / `Drop` / `Reset` など、アクションに関わらず atomic 化します。
- 途中で失敗した場合、未完了の atomic 結果はロールバックされ、既存結果は保持されます。

### merge

- atomic 化済みルールを、ゾーン・アプリケーション・アクション・サービス種別などの条件で統合します。
- 先頭のポート マージでは、`Kind` が同じなら IP プロトコル番号の違いを吸収します。
- Allow ルールは、サービス差分 -> 送信元差分 -> 宛先差分の順に 3 パスで統合します。
- 3 パス後に、同じ `FromZone` / `ToZone` / `Application` / `Action` / `GroupId` を持つ候補同士を比較し、宛先アドレスとサービスの各軸で左右それぞれ 80% 以上一致するペアを、共通部 1 件と残差へ再編成します。
- 再編成時の共通部は左右の送信元 Union と共通宛先・共通サービスで構成し、残差は各候補の元の送信元を保ったまま宛先差分とサービス差分で作成します。共通部だけを次の比較対象として再利用します。
- 非 Allow ルールは atomic のまま扱い、同じ元ルール由来の要素だけを merged 側で束ねます。
- 先行ルールが後続ルールを完全に覆う場合は、元インデックスが小さい側を採用します。
- `--wkport` と `--wkpthreshold` を併用すると、よく使われる宛先ポートだけで構成された小さな集合について、宛先アドレス集約を抑止できます。
- 高一致率再編成でも、共通サービス集合が `--wkport` / `--wkpthreshold` 条件に当たるペアは、そのペアだけスキップします。
- 統合元のインデックス範囲が別アクションと重なる場合は、警告ログへ詳細を出力します。
- 途中で失敗した場合、未完了の merge 結果はロールバックされ、既存結果は保持されます。

### export

- `target` に応じて atomic / merged の CSV を出力します。
- Merged 出力時は、import 済みのアドレス グループ情報が利用可能であれば、可能な範囲でグループ表現を再利用します。
- 出力文字コードは `--encoding` で指定します。
- UTF-8 BOM 付きで出力する場合は `--withbom` を指定します。

### test

- `merge` 済みの `merged_security_policies` が、shadowed 除去後 atomic の挙動を保持しているかを検査します。
- 比較対象の atomic は単なる全件ではなく、`merge` と同じ shadow 判定を適用したうえで扱います。
- shadowed に落ちた atomic も検査対象に含め、不一致は `warning` ではなく `informational` として記録します。
- `test` 自体は DB を更新しません。
- 進捗ログは `merge` と同じく 2000 件ごとに出力します。

### stat

- 現在の DB 状態を手早く確認したいときに使います。
- import / atomize / merge の完了有無と件数を表示します。
- 途中段階でも実行できます。

## 設定ファイル例

既定では `fwrule-tool.json` を読み込みます。

```json
{
    "database": "fwrule-tool-db",
    "logtype": "ConsoleOnly",
    "logfile": "fwrule-tool.log",
    "loglevel": "Information",
    "import": {
        "encoding": "utf-8",
        "withbom": true,
        "securitypolicies": "input_securitypolicies.csv",
        "addresses": "input_addresses.csv",
        "addressgroups": "input_addressgroups.csv",
        "services": "input_services.csv",
        "servicegroups": "input_servicegroups.csv"
    },
    "atomize": {
        "threshold": 25
    },
    "merge": {
        "wkport": "20,21,22,23,80,443,3389",
        "wkpthreshold": 3,
        "hspercent": 80
    },
    "export": {
        "encoding": "utf-8",
        "withbom": true,
        "target": "Merged",
        "atomic": "output_atomic.csv",
        "merged": "output_merged.csv"
    },
    "stat": {}
}
```

## help の見方

全体ヘルプ:

```powershell
fwrule-tool --help
```

サブコマンドごとのヘルプ:

```powershell
fwrule-tool import --help
fwrule-tool atomize --help
fwrule-tool merge --help
fwrule-tool test --help
fwrule-tool export --help
fwrule-tool stat --help
```

## 典型的な実行例

```powershell
fwrule-tool import `
  --database work-db `
  --securitypolicies .\input_securitypolicies.csv `
  --addresses .\input_addresses.csv `
  --addressgroups .\input_addressgroups.csv `
  --services .\input_services.csv `
  --servicegroups .\input_servicegroups.csv

fwrule-tool atomize --database work-db --threshold 25
fwrule-tool merge --database work-db --hspercent 80 --wkport 20,21,22,23,80,443,3389 --wkpthreshold 3
fwrule-tool test --database work-db
fwrule-tool export --database work-db --target Atomic,Merged --atomic .\atomic.csv --merged .\merged.csv
fwrule-tool stat --database work-db
```
