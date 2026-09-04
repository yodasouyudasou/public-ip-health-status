# Public IP Health Status

公開IPリファレンスに掲載している公開DNS、ルートDNS、NTPを、毎日 06:15 JST にプロトコル別で確認します。

- 公開再帰DNS: `example.com A` を UDP/53 で問い合わせ
- ルートDNS: `.` の NS を UDP/53 で問い合わせ
- 公開NTP: NTP Client request を UDP/123 で送信
- ICMP echo: 補助情報として記録（総合判定はサービス応答を優先）

GitHub Actions の IPv6 経路が使えない場合、IPv6 は停止扱いにせず `unknown` とします。結果は `health.json` に保存されます。

## 判定の意味

- `up`: 指定プロトコルの有効な応答を確認。
- `degraded`: ICMPには応答したが、指定プロトコルの応答を確認できない。
- `down`: この監視環境から応答を確認できない。サービス停止の断定ではない。
- `unknown`: IPv6経路など監視環境の制約、または初回確認前。

1日1回の観測結果であり、現在の可用性・SLA・時刻精度・利用者側の到達性を保証しません。DNSはUDP/53、NTPはUDP/123のみを確認し、DoH/DoT/NTS等の動作は保証しません。予約アドレス、プライベートIP、文書用アドレス、マルチキャストは対象外です。NTPのLI=3、Stratum=0/16以上、送信時刻の不正や要求と一致しない応答は正常としません。

## 実行

`Actions → Daily public IP health check → Run workflow` で手動実行できます。標準の `ubuntu-latest` を使い、Publicリポジトリで無料の構成です。成果物アップロード・キャッシュ・外部有料APIは使いません。ワークフロー内で必要な `contents: write` のみを指定しているため、アカウント全体の権限拡大やPATの追加は不要です。

GitHubのスケジュールは混雑によって遅延・実行漏れが起こり得ます。Web側では36時間以上古い結果を「更新遅延」と表示します。初回および監視コード変更時にも実行し、結果JSONの更新では再実行しません。

検証: `python -m unittest -v test_monitor.py`

出典: [GitHub schedule](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule) / [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) / [NTP RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)
