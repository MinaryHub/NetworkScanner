using System.Collections.Generic;

namespace NetworkScanner
{
    // 사용 설명서 콘텐츠. 앱 UI 언어(en/ko)와 별개로 영어(기본)·한국어·일본어·중국어를 지원하며,
    // 설명서 화면의 언어 콤보로 즉시 전환된다. 두 UI가 공유하도록 Core에 둔다.
    public static class UserGuide
    {
        public sealed record Section(string Heading, string Body);

        // (언어 코드, 콤보에 표시할 원어 이름). 첫 항목(영어)이 기본이다.
        public static readonly (string Code, string DisplayName)[] Languages =
        {
            ("en", "English"),
            ("ko", "한국어"),
            ("ja", "日本語"),
            ("zh", "中文"),
        };

        // 기본 언어: 영어. 단, 앱 UI가 한국어로 설정돼 있으면 한국어를 먼저 보여준다.
        public static string DefaultLanguage => Localization.IsKorean ? "ko" : "en";

        public static IReadOnlyList<Section> GetSections(string lang) => lang switch
        {
            "ko" => Korean,
            "ja" => Japanese,
            "zh" => Chinese,
            _ => English,
        };

        private static readonly Section[] English =
        {
            new("Overview",
                "Network Scanner discovers the devices on your network. It pings every IP in the configured " +
                "ranges, then collects each live host's open TCP ports, MAC address and vendor, and host name. " +
                "Results can be saved as CSV, exported as HTML/JSON reports, and optionally uploaded to a " +
                "server (FTPS, SFTP or HTTPS). Open ports are checked against a list of ports commonly abused by backdoors, and " +
                "matching hosts are flagged."),
            new("Running a scan",
                "Open the IP List screen and press Scan. The scan runs in two phases: phase 1 quickly pings the " +
                "whole range, so live hosts appear within seconds; phase 2 then fills in the details (MAC, " +
                "vendor, host name, open ports) in the background. Press Cancel to stop at any time. Row " +
                "colors: green = up, yellow = warning (a risky port is open), gray = no response."),
            new("IP scan ranges",
                "In Settings, add one or more ranges with a start and end IP. You can also type CIDR notation " +
                "(e.g. 192.168.1.0/24) into the start-IP field to fill both fields at once. Ranges may span " +
                "subnet boundaries. On first launch, the subnet of the active network adapter is added " +
                "automatically. Press 'Save settings' to keep your changes."),
            new("Port scan & risky ports",
                "Enable 'Port scan' in Settings and list the ports to check, separated by '/' (e.g. 22/80/443). " +
                "Open ports found on each host are shown in the 'Open Ports' column and compared against the " +
                "risky-port list; a match marks the row as a warning. The 'Ref. Ports' screen shows the " +
                "built-in reference lists: common reserved ports, and ports frequently used by backdoors and " +
                "trojans."),
            new("Working with the results",
                "Use the search box to filter by IP, name, port, MAC, vendor or note, and 'Alive only' to hide " +
                "hosts that did not respond. The Name and Note columns are editable; values you enter are " +
                "remembered per IP and merged into future scans automatically. Right-click a row for actions: " +
                "send a ping, check the configured/reserved/risky ports of that host, send Wake-on-LAN, or " +
                "remove the row."),
            new("Saving & reports",
                "'Save' writes the current list to a CSV file; 'Open' loads a previous one; 'New' clears the " +
                "list. 'Report' exports a formatted HTML or JSON report. All files are kept in the 'env' folder " +
                "inside your user-data directory (%APPDATA%\\NetworkScanner on Windows, " +
                "~/Library/Application Support/NetworkScanner on macOS, ~/.config/NetworkScanner on Linux), which survives updates. Enable 'Load latest file on " +
                "startup' to restore the most recent results automatically."),
            new("Scheduling, monitoring & upload",
                "Enable Scheduling and tick hours of the day: a scan then starts automatically at the beginning " +
                "of each ticked hour and saves a CSV and an HTML report by itself. Continuous monitoring " +
                "rescans every N minutes instead. When a scan detects changes - a new host, a host going " +
                "offline, a changed MAC address, or a newly opened/risky port - a security-alert dialog lists " +
                "them. If result upload is enabled, saved files are also sent to the configured server " +
                "(FTPS/SFTP/HTTPS); failed uploads are queued and retried automatically."),
            new("History & notifications",
                "Every scan is recorded in a local database. The History screen lists past scans and an " +
                "inventory of every device ever seen (first/last seen, last MAC, last open ports); use " +
                "'Prune' to delete old scans. In Settings you can also enable notifications so that detected " +
                "changes are posted to a webhook (Slack/Teams), a syslog server or sent by e-mail. The " +
                "headless scheduler service (netscan-service) runs the same schedule without the GUI."),
            new("Updates",
                "The app checks GitHub for a newer version at startup. When one is found, an Update button " +
                "appears at the bottom of the sidebar; click it to download the update and restart into the " +
                "new version. Your settings and scan history are preserved across updates."),
            new("FAQ",
                "Q. The MAC address column is often empty.\n" +
                "A. MAC addresses can only be resolved by ARP inside your own subnet. Hosts behind a router or " +
                "on another VLAN cannot be resolved (a protocol limitation, not an error), and the scanning PC " +
                "itself shows no MAC either. On busy Wi-Fi, occasional ARP replies may also be lost.\n\n" +
                "Q. The response time shows 'TCP'.\n" +
                "A. The host ignored ping (ICMP) but answered on a common TCP port, so it is marked alive.\n\n" +
                "Q. How do I change the app language?\n" +
                "A. In Settings, choose the language (English/Korean); it applies after restarting the app."),
        };

        private static readonly Section[] Korean =
        {
            new("개요",
                "Network Scanner는 네트워크에 연결된 장비를 찾아줍니다. 설정한 대역의 모든 IP에 Ping을 보낸 뒤, " +
                "살아있는 호스트의 열린 TCP 포트, MAC 주소와 제조사, 호스트 이름을 수집합니다. 결과는 CSV로 저장하고 " +
                "HTML/JSON 리포트로 내보낼 수 있으며, 서버 업로드(FTPS/SFTP/HTTPS)도 지원합니다. 열린 포트는 백도어가 자주 쓰는 " +
                "포트 목록과 비교해 해당 호스트를 경고로 표시합니다."),
            new("스캔 실행",
                "IP 리스트 화면에서 스캔 버튼을 누르세요. 스캔은 2단계로 진행됩니다. 1단계는 대역 전체를 빠르게 " +
                "Ping해 살아있는 호스트를 수 초 안에 표시하고, 2단계는 상세 정보(MAC, 제조사, 호스트 이름, 열린 " +
                "포트)를 백그라운드에서 채웁니다. 취소 버튼으로 언제든 중단할 수 있습니다. 행 색상: 초록 = 정상, " +
                "노랑 = 주의(위험 포트 열림), 회색 = 응답 없음."),
            new("IP 검색 대역",
                "설정 화면에서 시작 IP와 종료 IP로 대역을 추가합니다. 시작 IP 칸에 CIDR 표기(예: 192.168.1.0/24)를 " +
                "입력하면 두 칸이 한 번에 채워집니다. 대역은 서브넷 경계를 넘어도 됩니다. 처음 실행하면 현재 네트워크 " +
                "어댑터의 서브넷이 자동으로 추가됩니다. '설정 저장'을 눌러야 변경이 보존됩니다."),
            new("포트 검색과 위험 포트",
                "설정에서 'Port 검색 사용'을 켜고 검색할 포트 번호를 '/'로 구분해 입력하세요(예: 22/80/443). 발견된 " +
                "열린 포트는 '열린 Port' 컬럼에 표시되고 위험 포트 목록과 비교되어, 일치하면 해당 행이 주의로 " +
                "표시됩니다. '참고. 포트정보' 화면에서 기본 제공되는 예약 포트와 백도어/트로이 목마가 자주 쓰는 포트 " +
                "목록을 볼 수 있습니다."),
            new("결과 다루기",
                "검색창에 입력하면 IP/이름/포트/MAC/제조사/비고로 필터링되고, '살아있는 것만'을 켜면 응답 없는 " +
                "호스트가 숨겨집니다. 이름과 비고 컬럼은 직접 수정할 수 있으며, 입력한 값은 IP 기준으로 기억되어 다음 " +
                "스캔에도 자동으로 병합됩니다. 행을 우클릭하면 Ping 보내기, 설정/예약/위험 포트 검사, " +
                "Wake-on-LAN(원격 켜기), 삭제를 실행할 수 있습니다."),
            new("저장과 리포트",
                "'파일 저장'은 현재 목록을 CSV로 저장하고, '파일 열기'는 이전 CSV를 불러오며, '새로 만들기'는 목록을 " +
                "비웁니다. '리포트'는 보기 좋은 HTML 또는 JSON 리포트를 내보냅니다. 모든 파일은 사용자 데이터 " +
                "폴더(Windows: %APPDATA%\\NetworkScanner, macOS: ~/Library/Application Support/NetworkScanner, Linux: ~/.config/NetworkScanner) 안의 env 폴더에 " +
                "저장되어 업데이트 후에도 유지됩니다. '시작시 최근 기록 부르기'를 켜면 시작할 때 가장 최근 결과를 " +
                "자동으로 불러옵니다."),
            new("스케줄링·모니터링·업로드",
                "스케줄링을 켜고 시간대를 체크하면, 체크한 시각의 정각마다 스캔이 자동 실행되고 CSV와 HTML 리포트가 " +
                "자동 저장됩니다. 연속 모니터링은 N분 간격으로 계속 재스캔합니다. 스캔에서 변화(새 호스트, 오프라인 " +
                "전환, MAC 변경, 새로 열린/위험 포트)가 감지되면 보안 경고 대화상자로 알려줍니다. 결과 업로드를 켜면 " +
                "저장된 파일이 설정한 서버(FTPS/SFTP/HTTPS)로도 전송되며, 실패한 업로드는 대기열에 넣어 자동으로 재시도합니다."),
            new("이력·알림",
                "모든 스캔은 로컬 데이터베이스에 기록됩니다. 이력 화면에서 과거 스캔 목록과 지금까지 발견된 모든 장비의 " +
                "인벤토리(최초/최근 발견, 마지막 MAC, 마지막 열린 포트)를 볼 수 있고, '정리'로 오래된 스캔을 지울 수 " +
                "있습니다. 설정에서 알림을 켜면 감지된 변화를 웹훅(Slack/Teams), syslog 서버, 이메일로 보냅니다. " +
                "헤드리스 스케줄러 서비스(netscan-service)는 GUI 없이 같은 스케줄을 실행합니다."),
            new("업데이트",
                "앱은 시작할 때 GitHub에서 새 버전을 확인합니다. 새 버전이 있으면 사이드바 하단에 업데이트 버튼이 " +
                "나타나며, 누르면 다운로드 후 새 버전으로 재시작됩니다. 설정과 스캔 기록은 업데이트 후에도 유지됩니다."),
            new("자주 묻는 질문",
                "Q. MAC 주소가 자주 비어 있어요.\n" +
                "A. MAC은 같은 서브넷 안에서만 ARP로 알아낼 수 있습니다. 라우터 건너편이나 다른 VLAN의 호스트는 " +
                "원리상 조회할 수 없고(오류가 아님), 스캔하는 PC 자신의 MAC도 표시되지 않습니다. 혼잡한 Wi-Fi에서는 " +
                "ARP 응답이 가끔 유실되기도 합니다.\n\n" +
                "Q. 응답시간에 'TCP'라고 표시돼요.\n" +
                "A. 해당 호스트가 Ping(ICMP)에는 응답하지 않았지만 대표 TCP 포트로 생존이 확인된 경우입니다.\n\n" +
                "Q. 앱 언어는 어떻게 바꾸나요?\n" +
                "A. 설정 화면에서 언어(English/한국어)를 선택하면 재시작 후 적용됩니다."),
        };

        private static readonly Section[] Japanese =
        {
            new("概要",
                "Network Scanner はネットワーク上の機器を検出するツールです。設定した範囲のすべての IP に Ping を" +
                "送り、応答したホストの開いている TCP ポート、MAC アドレスとベンダー、ホスト名を収集します。結果は " +
                "CSV に保存でき、HTML/JSON レポートへの出力やサーバー(FTPS/SFTP/HTTPS)へのアップロードにも対応します。開いている" +
                "ポートはバックドアがよく使うポートの一覧と照合され、該当するホストは警告として表示されます。"),
            new("スキャンの実行",
                "IP リスト画面でスキャンボタンを押します。スキャンは 2 段階で進みます。第 1 段階では範囲全体を高速に " +
                "Ping し、応答のあるホストを数秒で表示します。第 2 段階では詳細情報(MAC、ベンダー、ホスト名、開いて" +
                "いるポート)をバックグラウンドで取得します。キャンセルボタンでいつでも中断できます。行の色: 緑 = " +
                "正常、黄 = 警告(危険なポートが開いている)、グレー = 応答なし。"),
            new("IP スキャン範囲",
                "設定画面で開始 IP と終了 IP を指定して範囲を追加します。開始 IP 欄に CIDR 表記(例: " +
                "192.168.1.0/24)を入力すると両方の欄が自動で埋まります。範囲はサブネット境界をまたいでも構いません。" +
                "初回起動時には、使用中のネットワークアダプターのサブネットが自動で追加されます。変更は「設定を保存」で" +
                "保存してください。"),
            new("ポートスキャンと危険なポート",
                "設定で「ポートスキャン」を有効にし、検査するポート番号を「/」区切りで入力します(例: 22/80/443)。" +
                "検出された開いているポートは「Open Ports」列に表示され、危険ポート一覧と照合されます。一致した行は" +
                "警告として表示されます。「参照ポート」画面では、内蔵の参照リスト(主な予約ポート、バックドアや" +
                "トロイの木馬がよく使うポート)を確認できます。"),
            new("結果の操作",
                "検索ボックスで IP・名前・ポート・MAC・ベンダー・備考を絞り込めます。「応答ありのみ」を有効にすると" +
                "無応答のホストを非表示にします。名前と備考の列は編集可能で、入力した値は IP ごとに記憶され、以降の" +
                "スキャン結果にも自動で引き継がれます。行を右クリックすると、Ping 送信、設定/予約/危険ポートの検査、" +
                "Wake-on-LAN、行の削除が実行できます。"),
            new("保存とレポート",
                "「保存」は現在のリストを CSV に書き出し、「開く」は以前の CSV を読み込み、「新規」はリストをクリア" +
                "します。「レポート」は整形済みの HTML または JSON レポートを出力します。ファイルはすべてユーザー" +
                "データフォルダー(Windows: %APPDATA%\\NetworkScanner、macOS: ~/Library/Application Support/NetworkScanner、Linux: ~/.config/NetworkScanner)内の " +
                "env フォルダーに保存され、アップデート後も保持されます。「起動時に最新ファイルを読み込む」を有効に" +
                "すると、起動時に最新の結果を自動で復元します。"),
            new("スケジュール・監視・アップロード",
                "スケジュールを有効にして時間帯にチェックを入れると、チェックした時刻の毎正時にスキャンが自動実行され、" +
                "CSV と HTML レポートが自動保存されます。連続監視は N 分間隔で再スキャンを繰り返します。スキャンで" +
                "変化(新しいホスト、オフライン化、MAC アドレスの変更、新たに開いた/危険なポート)を検出すると、" +
                "セキュリティ警告ダイアログで一覧表示します。結果アップロードを有効にすると、保存したファイルは設定" +
                "したサーバー(FTPS/SFTP/HTTPS)にも送信され、失敗したアップロードはキューに入れて自動的に再試行されます。"),
            new("履歴・通知",
                "すべてのスキャンはローカルデータベースに記録されます。履歴画面では過去のスキャン一覧と、これまでに" +
                "検出した全機器のインベントリ(初回/最終検出、最後の MAC、最後の開放ポート)を確認でき、「整理」で古い" +
                "スキャンを削除できます。設定で通知を有効にすると、検出した変化を Webhook(Slack/Teams)、syslog " +
                "サーバー、メールで送信します。ヘッドレスのスケジューラーサービス(netscan-service)は GUI なしで同じ" +
                "スケジュールを実行します。"),
            new("アップデート",
                "アプリは起動時に GitHub で新しいバージョンを確認します。新しいバージョンが見つかると、サイドバー" +
                "下部にアップデートボタンが表示されます。クリックするとダウンロード後、新しいバージョンで再起動" +
                "します。設定とスキャン履歴はアップデート後も保持されます。"),
            new("よくある質問",
                "Q. MAC アドレス列が空になることが多い。\n" +
                "A. MAC アドレスは同一サブネット内でのみ ARP で取得できます。ルーターの先や別 VLAN のホストは原理的に" +
                "取得できず(エラーではありません)、スキャンしている PC 自身の MAC も表示されません。混雑した Wi-Fi " +
                "では ARP 応答が失われることもあります。\n\n" +
                "Q. 応答時間に「TCP」と表示される。\n" +
                "A. そのホストは Ping (ICMP) に応答しませんでしたが、代表的な TCP ポートで生存が確認されたことを示し" +
                "ます。\n\n" +
                "Q. アプリの言語を変えるには?\n" +
                "A. 設定画面で言語(English/한국어)を選択すると、再起動後に適用されます。"),
        };

        private static readonly Section[] Chinese =
        {
            new("概述",
                "Network Scanner 用于发现网络中的设备。它对设定范围内的所有 IP 发送 Ping,然后收集每台在线主机的" +
                "开放 TCP 端口、MAC 地址与厂商、主机名。结果可保存为 CSV,导出为 HTML/JSON 报告,并可选上传到" +
                "服务器(FTPS/SFTP/HTTPS)。开放端口会与后门程序常用端口列表比对,匹配的主机将被标记为警告。"),
            new("运行扫描",
                "打开 IP 列表界面,点击扫描按钮。扫描分两个阶段:第一阶段快速 Ping 整个范围,在线主机几秒内即会显示;" +
                "第二阶段在后台补全详细信息(MAC、厂商、主机名、开放端口)。随时可点击取消停止。行颜色:绿色 = 正常," +
                "黄色 = 警告(存在危险端口),灰色 = 无响应。"),
            new("IP 扫描范围",
                "在设置界面中,通过起始 IP 和结束 IP 添加一个或多个范围。也可以在起始 IP 栏输入 CIDR 表示法(例如 " +
                "192.168.1.0/24),两栏会自动填充。范围可以跨越子网边界。首次启动时会自动添加当前网卡所在的子网。" +
                "请点击“保存设置”以保留更改。"),
            new("端口扫描与危险端口",
                "在设置中启用“端口扫描”,并用“/”分隔要检查的端口号(例如 22/80/443)。发现的开放端口显示在" +
                "“开放端口”列中,并与危险端口列表比对,匹配的行将标记为警告。“参考端口”界面提供内置参考列表:" +
                "常见保留端口,以及后门和木马常用的端口。"),
            new("使用扫描结果",
                "在搜索框中输入即可按 IP、名称、端口、MAC、厂商或备注过滤;启用“仅显示在线”可隐藏无响应的主机。" +
                "名称和备注列可直接编辑,输入的内容会按 IP 记忆,并自动合并到以后的扫描结果中。右键点击行可执行操作:" +
                "发送 Ping、检查该主机的配置/保留/危险端口、发送网络唤醒(Wake-on-LAN)、删除该行。"),
            new("保存与报告",
                "“保存”将当前列表写入 CSV 文件;“打开”载入以前的 CSV;“新建”清空列表。“报告”可导出排版好的 " +
                "HTML 或 JSON 报告。所有文件保存在用户数据目录(Windows: %APPDATA%\\NetworkScanner,macOS: ~/Library/Application Support/NetworkScanner,Linux: " +
                "~/.config/NetworkScanner)下的 env 文件夹中,更新后不会丢失。启用“启动时载入最新文件”可在启动时" +
                "自动恢复最近的结果。"),
            new("计划任务、监控与上传",
                "启用计划任务并勾选小时:在勾选的每个整点会自动开始扫描,并自动保存 CSV 和 HTML 报告。持续监控则每隔 " +
                "N 分钟重新扫描一次。当扫描检测到变化(新主机、主机离线、MAC 地址变化、新开放/危险端口)时,会弹出" +
                "安全警告对话框列出详情。启用结果上传后,保存的文件还会发送到设定的服务器(FTPS/SFTP/HTTPS);上传失败会进入队列并自动重试。"),
            new("历史与通知",
                "每次扫描都会记录到本地数据库。历史界面列出过去的扫描以及曾发现的所有设备清单(首次/最近发现、最近 MAC、" +
                "最近开放端口),可用“清理”删除旧扫描。在设置中启用通知后,检测到的变化会推送到 Webhook(Slack/Teams)、" +
                "syslog 服务器或通过邮件发送。无界面的计划服务(netscan-service)可在没有 GUI 的情况下执行相同的计划。"),
            new("更新",
                "应用启动时会在 GitHub 上检查新版本。发现新版本时,侧边栏底部会出现更新按钮;点击即可下载并重启到" +
                "新版本。设置和扫描记录在更新后会保留。"),
            new("常见问题",
                "Q. MAC 地址列经常是空的。\n" +
                "A. MAC 地址只能通过 ARP 在本子网内解析。路由器之后或其他 VLAN 中的主机原理上无法解析(这不是错误)," +
                "扫描所用的电脑本身也不显示 MAC。在繁忙的 Wi-Fi 中,ARP 应答偶尔也会丢失。\n\n" +
                "Q. 响应时间显示为“TCP”。\n" +
                "A. 该主机未响应 Ping (ICMP),但在常见 TCP 端口上确认存活。\n\n" +
                "Q. 如何更改应用语言?\n" +
                "A. 在设置界面选择语言(English/한국어),重启后生效。"),
        };
    }
}
