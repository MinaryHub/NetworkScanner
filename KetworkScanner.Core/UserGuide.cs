using System.Collections.Generic;

namespace KetworkScanner
{
    // 사용 설명서 콘텐츠. 앱 UI 언어(en/ko)와 같은 두 언어를 제공하며, 설명서 화면의 언어 콤보로 즉시 전환된다.
    // 두 UI가 공유하도록 Core에 둔다. 섹션 구조(Heading/Body)는 언어마다 같아야 한다(UserGuideTests가 검사).
    public static class UserGuide
    {
        public sealed record Section(string Heading, string Body);

        // (언어 코드, 콤보에 표시할 원어 이름). 첫 항목(영어)이 기본이다.
        public static readonly (string Code, string DisplayName)[] Languages =
        {
            (Localization.English, "English"),
            (Localization.Korean, "한국어"),
        };

        // 기본 언어: 영어. 단, 앱 UI가 한국어로 설정돼 있으면 한국어를 먼저 보여준다.
        public static string DefaultLanguage => Localization.IsKorean ? Localization.Korean : Localization.English;

        public static IReadOnlyList<Section> GetSections(string lang) => lang switch
        {
            Localization.Korean => Korean,
            _ => English,
        };

        private static readonly Section[] English =
        {
            new("Overview",
                "Ketwork Scanner keeps an inventory of the devices on your network. It pings every IP in the configured " +
                "ranges, then collects each live host's open TCP ports, MAC address and vendor, host name, model, OS and " +
                "switch port, scores each host for risk, and records everything in a local history database. Results can " +
                "be saved as CSV, exported as HTML/JSON/PDF reports, uploaded to a server (FTPS, SFTP or HTTPS) and turned " +
                "into alerts (webhook, syslog, e-mail). Only scan networks you own or are explicitly authorized to scan."),
            new("Navigation",
                "The sidebar has five screens. IP List is the scan screen with the result table. History holds the past " +
                "scans, the host inventory (asset approval, owner/tags) and the alert list (acknowledge/snooze). Settings " +
                "holds every option described below. Ref. Ports shows the built-in reference lists of reserved ports and " +
                "ports commonly used by backdoors and trojans. Guide is this document. The bottom of the sidebar shows the " +
                "number of open alerts, the number of uploads waiting in the outbox, and an Update button when a new version " +
                "is available."),
            new("Running a scan",
                "On the IP List screen choose a scan profile in the toolbar combo - Quick (ping only, fewest ports), " +
                "Standard, or Thorough (more ports, longer timeouts, every probe) - and press Scan. Phase 1 pings the whole " +
                "range in parallel, so live hosts appear within seconds; phase 2 then fills in the details (MAC, vendor, " +
                "name, open ports, fingerprints, risk) in the background. Press Cancel to stop at any time. Rows are " +
                "coloured by status: a green dot means up, a red triangle on a red-tinted row means a risky port is open " +
                "or the risk score is high, and a grey ring with grey text means no response. The summary tiles above the " +
                "table count addresses, live hosts, risky hosts, silent hosts and the rows currently shown."),
            new("IP scan ranges",
                "In Settings, add one or more ranges with a start and end IP. You can also type CIDR notation " +
                "(e.g. 192.168.1.0/24) into the start-IP field to fill both fields at once. Ranges may span subnet " +
                "boundaries. On first launch, the subnet of the active network adapter is added automatically. " +
                "'Max addresses' in Scan limits caps the total number of addresses a single scan may touch. Press " +
                "'Save settings' to keep your changes."),
            new("Columns, search and filters",
                "The table shows Status, IP, Name, Type, OS (guess), Model, OS version, Open Ports, Service (banner), MAC, " +
                "Vendor, RTT, Switch port, Note, Added, Risk and Approved. Name and Note are editable; values you enter " +
                "are remembered per IP and merged into future scans. Drag column borders to resize - widths are saved per " +
                "column. The search box matches IP, name, type, OS, model, OS version, ports, service, MAC, vendor, switch " +
                "port and note. 'Alive only' hides hosts that did not respond and 'Risky only' shows just the red rows."),
            new("Context menu",
                "Right-click a row for: Ping (one manual ping), Check ports (a submenu with the configured ports, all " +
                "reserved ports, or all risky ports of that host), Details… (the host details window, also opened by " +
                "double-click), Approve as known asset / Unapprove, Wake-on-LAN (sends a magic packet to the host's MAC) " +
                "and Remove (drops the row from the list)."),
            new("Host details",
                "The details window shows the identity of one host - model, MAC, vendor, IPv6 address, OS and OS version, " +
                "device type, switch port, risk score, approval, open ports, service banner, SNMP system description and " +
                "the source of the name - followed by the vulnerability findings (severity, title, port and reference) and " +
                "the Evidence list. Evidence is every fact the probes collected, with the value, the probe that reported it " +
                "(e.g. smb, ssh, http, ssdp, mdns, snmp, lldp, history:…) and its confidence, so you can see why a host was " +
                "classified the way it was."),
            new("Port scan and risky ports",
                "Enable 'Enable port scan' in Settings and list the ports to check, separated by '/' (e.g. 22/80/443); " +
                "the Thorough profile adds a built-in top-ports list. Open ports are compared with the risky-port list and " +
                "a match marks the row red. 'Risky-port exceptions' whitelists known-good cases: a bare port (8080), " +
                "ip:port (10.0.0.5:31337) or cidr:port (10.0.1.0/24:12345). 'Assess vulnerabilities' needs the port scan, " +
                "because the rules are matched against open ports and banners."),
            new("Deep discovery",
                "The Deep discovery card in Settings has three rows. Names: NetBIOS, mDNS PTR and SNMP system info " +
                "(community string) resolve host names and the SNMP system description. Fingerprints, run against each " +
                "live host: SMB (Windows edition/build and computer name from the SMB2/NTLM negotiation), SSH (distribution " +
                "from the banner), HTTP/TLS (server header, page title, vendor web UIs, certificate names) and UDP " +
                "services (DNS, NTP, SSDP unicast, TFTP, SIP). Network, run once per scan: SSDP/UPnP (device description " +
                "XML: model, manufacturer), mDNS browsing (Bonjour services, Apple models), OS neighbour tables (the " +
                "scanner's own ARP/NDP cache, giving IPv6 addresses), gateway SNMP tables and extra SNMP devices " +
                "(ARP, bridge forwarding and LLDP tables, which give the switch port), active ARP (Linux only, needs " +
                "CAP_NET_RAW) and the passive listener (captures ARP/DHCP/mDNS traffic with libpcap/npcap; needs " +
                "administrator or root and the capture driver). 'Merge facts from earlier scans' keeps values seen in " +
                "previous scans at lower confidence. Except for the merge option, changes on this card take effect after " +
                "a restart."),
            new("Saving and reports",
                "'Save' writes the current list to a CSV file, 'Open' loads a previous one and 'Clear' empties the list. " +
                "'Report' exports an HTML, JSON or PDF report (PDF embeds a Korean-capable font). Files are kept in the " +
                "'env' folder inside your user-data directory (%APPDATA%\\KetworkScanner on Windows, " +
                "~/Library/Application Support/KetworkScanner on macOS, ~/.config/KetworkScanner on Linux), which " +
                "survives updates. 'Load latest file on startup' restores the most recent results automatically. The " +
                "system name is used as the prefix of every saved file and is required when upload is enabled."),
            new("Scheduling and continuous monitoring",
                "Enable scheduling and tick hours of the day (00-23): a scan then starts once in each ticked hour and " +
                "saves a CSV, an HTML report and a PDF by itself; if the app was asleep at the top of the hour it still " +
                "runs later in that hour. Continuous monitoring rescans every N minutes instead, without autosaving. " +
                "Every scan is compared with the previous one: new or returning hosts, hosts going offline, changed MAC " +
                "addresses, newly opened or risky ports, unapproved devices and high risk scores are reported as changes, " +
                "and security-relevant ones pop up in a dialog."),
            new("Upload",
                "With result upload enabled, every autosaved CSV and report is sent to the configured server. Protocols: " +
                "FTP (plain, must be explicitly allowed), FTPS explicit or implicit, SFTP, and HTTPS (multipart POST with " +
                "a Bearer token). Pin the server with its SHA-256 fingerprint - the TLS certificate for FTPS/HTTPS or the " +
                "host key for SFTP; without a pin, SFTP trusts the key on first use and stores it in known_hosts. " +
                "Passwords and tokens are kept in the OS credential store (or an encrypted file), never in settings.json. " +
                "Failed uploads go to the outbox and are retried with backoff at startup and after each scheduled scan; " +
                "the sidebar shows how many are waiting."),
            new("Notifications and alert operations",
                "Notifications send detected changes to a webhook (Slack/Teams/Discord), a UDP syslog server and/or by " +
                "e-mail (SMTP with optional STARTTLS). 'Security changes only' limits them to MAC changes, risky ports, " +
                "unapproved devices and high risk. Alerts are deduplicated per event in the History screen: acknowledge " +
                "or snooze them for 24 hours to stop re-notification, reopen them later, and set a re-notify interval " +
                "(hours) after which an unresolved alert is sent again. Maintenance windows (e.g. Mon-Fri 22:00-06:00; " +
                "Sat,Sun) record alerts but send nothing. State alerts resolve themselves when the condition disappears."),
            new("Asset approval",
                "The inventory on the History screen lists every device ever seen. Approve the ones you know - the MAC " +
                "seen at approval time is remembered - and give them an owner, tags and a note. 'Approve everything found " +
                "by the first scan' turns the first scan into a baseline. With 'Alert on unapproved devices' on, any other " +
                "live host raises an alert, and an approved IP answering with a different MAC is flagged as a MAC " +
                "mismatch. You can also approve or unapprove straight from the IP List context menu."),
            new("Vulnerability assessment and risk score",
                "Open ports, service banners and TLS settings are matched against an offline rule set (vulnerable " +
                "versions, weak protocols, exposed services, TLS problems, default configurations). Each finding has a " +
                "severity (Info, Low, Medium, High, Critical) and contributes to a 0-100 risk score; a score at or above " +
                "40 marks the row red, and the 'High-risk threshold' in Asset policy decides when a high-risk alert is " +
                "raised. The findings are listed in the host details window."),
            new("History, retention and backup",
                "Every scan is recorded in a SQLite database (history.db). The History screen lists recent scans and the " +
                "inventory with first/last seen, last model, OS, MAC and ports. 'Keep history (days)' in Backup & support " +
                "prunes older scans automatically (0 = forever) and the History screen's Prune button uses the same " +
                "number. A backup copy is written once a day and the newest N are kept; 'Backup now' writes one on demand " +
                "and 'Restore…' picks a backup that replaces the database at the next start."),
            new("Settings export, import and diagnostics",
                "'Export settings' writes settings and ranges to a JSON file without any secrets; 'Import settings' " +
                "loads such a file (the language applies after a restart). 'Create diagnostic bundle' zips the settings, " +
                "recent logs, environment details and a history summary for a support request. Settings are validated " +
                "on save: invalid numbers or hosts are listed and nothing is written until they are fixed."),
            new("Automatic updates",
                "The installed app checks GitHub Releases for a newer version at startup and every N hours, downloads it " +
                "in the background when 'Download updates in the background' is on, and - with 'Install when the app " +
                "closes' - applies it silently at exit; otherwise the sidebar Update button installs and restarts. " +
                "'Include pre-releases (beta)' follows the beta channel. 'Check now' runs a manual check. Settings and " +
                "history survive updates. Development builds started with dotnet run do not update."),
            new("Command line and service",
                "netscan is the command-line scanner (same engine): scan a range or use the saved settings, choose a " +
                "profile, write HTML/JSON/PDF reports, upload and notify, and manage history, assets, alerts, settings " +
                "export/import and the diagnostic bundle; it exits with code 3 when risky ports were found. " +
                "netscan-service is the headless scheduler that runs the same schedule from settings.json as a Windows " +
                "service, systemd unit or launchd agent, catching up a missed run after a restart."),
            new("FAQ",
                "Q. The MAC address column is often empty.\n" +
                "A. MAC addresses can only be resolved by ARP inside your own subnet. Hosts behind a router or on another " +
                "VLAN cannot be resolved (a protocol limitation, not an error), and the scanning PC itself shows no MAC " +
                "either. Gateway SNMP tables can fill the gap for routed segments.\n\n" +
                "Q. The RTT column shows 'TCP', 'MCAST' or 'TABLE'.\n" +
                "A. The host ignored ping but answered on a common TCP port, replied to multicast discovery, or was " +
                "listed in a neighbour/SNMP table, so it is marked alive.\n\n" +
                "Q. Ping is not permitted.\n" +
                "A. On Linux run 'sudo setcap cap_net_raw+ep <executable>' or run as root; on other systems run as " +
                "administrator.\n\n" +
                "Q. How do I change the app language?\n" +
                "A. In Settings, choose the language (English/Korean); it applies after restarting the app."),
        };

        private static readonly Section[] Korean =
        {
            new("개요",
                "Ketwork Scanner는 네트워크에 연결된 장비의 인벤토리를 관리합니다. 설정한 대역의 모든 IP에 Ping을 보낸 뒤, " +
                "살아있는 호스트의 열린 TCP 포트, MAC 주소와 제조사, 호스트 이름, 모델, OS, 스위치 포트를 수집하고, 호스트마다 " +
                "위험 점수를 매기며, 모든 결과를 로컬 이력 데이터베이스에 기록합니다. 결과는 CSV로 저장하고 HTML/JSON/PDF 리포트로 " +
                "내보내며, 서버(FTPS/SFTP/HTTPS)로 업로드하고 알림(웹훅/syslog/메일)으로 보낼 수 있습니다. 본인이 소유했거나 " +
                "명시적으로 허가받은 네트워크만 스캔하세요."),
            new("화면 구성",
                "사이드바에 다섯 화면이 있습니다. IP 리스트는 결과 표가 있는 스캔 화면입니다. 이력은 과거 스캔, 호스트 인벤토리" +
                "(자산 승인, 소유자·태그)와 알림 목록(확인/스누즈)을 담습니다. 설정에는 아래에서 설명하는 모든 옵션이 있습니다. " +
                "참고 포트정보는 예약 포트와 백도어·트로이 목마가 자주 쓰는 포트의 기본 제공 목록입니다. 사용 설명서가 이 문서입니다. " +
                "사이드바 하단에는 열린 알림 수, 대기 중 업로드 수, 새 버전이 있을 때의 업데이트 버튼이 표시됩니다."),
            new("스캔 실행",
                "IP 리스트 화면의 툴바 콤보에서 스캔 프로필 - 빠른 스캔(Ping만, 최소 포트), 표준, 정밀 스캔(더 많은 포트, 긴 타임아웃, " +
                "모든 프로브) - 을 고르고 스캔을 누르세요. 1단계는 대역 전체를 병렬로 Ping해 살아있는 호스트를 수 초 안에 표시하고, " +
                "2단계는 상세 정보(MAC, 제조사, 이름, 열린 포트, 핑거프린트, 위험도)를 백그라운드에서 채웁니다. 취소 버튼으로 " +
                "언제든 중단할 수 있습니다. 행은 상태별로 색이 다릅니다. 초록 점은 정상, 붉은 바탕의 빨간 삼각형은 위험 포트가 " +
                "열렸거나 위험 점수가 높은 호스트, 회색 고리와 회색 글자는 응답 없음입니다. 표 위의 요약 타일은 전체 주소, 정상, " +
                "위험, 응답 없음, 현재 표시 중인 행 수를 보여줍니다."),
            new("IP 검색 대역",
                "설정 화면에서 시작 IP와 종료 IP로 대역을 추가합니다. 시작 IP 칸에 CIDR 표기(예: 192.168.1.0/24)를 입력하면 두 칸이 " +
                "한 번에 채워집니다. 대역은 서브넷 경계를 넘어도 됩니다. 처음 실행하면 현재 네트워크 어댑터의 서브넷이 자동으로 " +
                "추가됩니다. 스캔 한계의 '최대 주소 수'는 한 번의 스캔이 두드릴 수 있는 주소 수의 상한입니다. '설정 저장'을 눌러야 " +
                "변경이 보존됩니다."),
            new("컬럼·검색·필터",
                "표에는 상태, IP, 이름, 종류, OS추정, 모델, OS 버전, 열린 Port, 서비스(배너), MAC, Vendor, 응답시간, 스위치 포트, 비고, " +
                "추가일, 위험도, 승인 컬럼이 있습니다. 이름과 비고는 직접 수정할 수 있으며 IP 기준으로 기억되어 다음 스캔에 병합됩니다. " +
                "컬럼 경계를 끌어 너비를 바꾸면 컬럼별로 저장됩니다. 검색창은 IP, 이름, 종류, OS, 모델, OS 버전, 포트, 서비스, MAC, " +
                "Vendor, 스위치 포트, 비고를 대상으로 합니다. '살아있는 것만'은 응답 없는 호스트를 숨기고 '위험만'은 빨간 행만 보여줍니다."),
            new("컨텍스트 메뉴",
                "행을 우클릭하면 Ping 보내기(수동 Ping 한 번), 포트 검사(설정된 Port / 예약 Port 전체 / 위험 Port 전체를 고르는 하위 " +
                "메뉴), 상세 정보…(더블클릭으로도 열리는 호스트 상세 창), 알려진 자산으로 승인 / 승인 해제, Wake-on-LAN(해당 MAC으로 " +
                "매직 패킷 전송), 삭제(목록에서 행 제거)를 실행할 수 있습니다."),
            new("호스트 상세",
                "상세 창은 호스트 한 대의 식별 정보 - 모델, MAC, 제조사, IPv6 주소, OS와 OS 버전, 장비 종류, 스위치 포트, 위험 점수, " +
                "승인 여부, 열린 포트, 서비스 배너, SNMP 시스템 설명, 이름 출처 - 와 취약점 발견 항목(심각도, 제목, 포트, 참고 링크), " +
                "그리고 근거 목록을 보여줍니다. 근거는 프로브가 수집한 모든 사실로, 값과 그 값을 알려준 프로브(smb, ssh, http, ssdp, " +
                "mdns, snmp, lldp, history:… 등), 신뢰도를 함께 표시해 호스트가 왜 그렇게 분류됐는지 확인할 수 있습니다."),
            new("포트 검색과 위험 포트",
                "설정에서 'Port 검색 사용'을 켜고 검색할 포트를 '/'로 구분해 입력하세요(예: 22/80/443). 정밀 스캔 프로필은 내장 " +
                "상위 포트 목록을 더합니다. 열린 포트는 위험 포트 목록과 비교되어 일치하면 행이 빨갛게 표시됩니다. '위험 포트 예외'에 " +
                "포트(8080), ip:port(10.0.0.5:31337), cidr:port(10.0.1.0/24:12345) 형식으로 알려진 정상 사례를 등록할 수 있습니다. " +
                "'취약점·약한 설정 평가'는 열린 포트와 배너에 규칙을 적용하므로 Port 검색이 켜져 있어야 합니다."),
            new("심층 발견",
                "설정의 심층 발견 카드는 세 줄입니다. 이름: NetBIOS, mDNS PTR, SNMP 시스템 정보(커뮤니티 문자열)로 호스트 이름과 " +
                "SNMP 시스템 설명을 얻습니다. 핑거프린트(살아있는 호스트마다 실행): SMB(SMB2/NTLM 협상에서 Windows 에디션·빌드와 " +
                "컴퓨터 이름), SSH(배너에서 배포판), HTTP/TLS(서버 헤더, 페이지 제목, 제조사 웹 UI, 인증서 이름), UDP 서비스" +
                "(DNS, NTP, SSDP 유니캐스트, TFTP, SIP). 네트워크(스캔마다 한 번 실행): SSDP/UPnP(장치 설명 XML의 모델·제조사), " +
                "mDNS 브라우징(Bonjour 서비스, Apple 모델), OS 이웃 테이블(스캐너 자신의 ARP/NDP 캐시, IPv6 주소), 게이트웨이 SNMP " +
                "테이블과 추가 SNMP 장비(ARP·브리지 포워딩·LLDP 테이블로 스위치 포트 파악), 능동 ARP(Linux 전용, CAP_NET_RAW 필요), " +
                "패시브 캡처(libpcap/npcap으로 ARP/DHCP/mDNS 트래픽 수집, 관리자/루트 권한과 캡처 드라이버 필요). '이전 스캔의 사실 " +
                "병합'은 이전 스캔에서 본 값을 낮은 신뢰도로 유지합니다. 병합 옵션을 제외한 이 카드의 변경은 재시작 후 적용됩니다."),
            new("저장과 리포트",
                "'파일 저장'은 현재 목록을 CSV로 저장하고, '파일 열기'는 이전 CSV를 불러오며, '목록 비우기'는 목록을 비웁니다. " +
                "'리포트'는 HTML, JSON 또는 PDF 리포트를 내보냅니다(PDF는 한글 글꼴을 내장). 파일은 사용자 데이터 폴더" +
                "(Windows: %APPDATA%\\KetworkScanner, macOS: ~/Library/Application Support/KetworkScanner, Linux: " +
                "~/.config/KetworkScanner) 안의 env 폴더에 저장되어 업데이트 후에도 유지됩니다. '시작시 최근 기록 부르기'를 켜면 " +
                "가장 최근 결과를 자동으로 불러옵니다. 시스템 이름은 저장되는 모든 파일 이름의 접두어이며 업로드를 켜면 필수입니다."),
            new("스케줄링과 연속 모니터링",
                "스케줄링을 켜고 시간대(00~23시)를 체크하면, 체크한 시간마다 한 번 스캔이 자동 실행되고 CSV, HTML 리포트, PDF가 " +
                "자동 저장됩니다. 정각에 앱이 절전 상태였더라도 그 시간 안에 한 번은 실행됩니다. 연속 모니터링은 대신 N분 간격으로 " +
                "자동 저장 없이 재스캔합니다. 모든 스캔은 직전 스캔과 비교되어 신규/재접속 호스트, 오프라인 전환, MAC 변경, 새로 " +
                "열린 포트나 위험 포트, 미승인 장비, 고위험 점수가 변화로 보고되고, 보안상 중요한 변화는 대화상자로 알립니다."),
            new("업로드",
                "결과 업로드를 켜면 자동 저장된 CSV와 리포트가 설정한 서버로 전송됩니다. 프로토콜: FTP(평문, 명시적으로 허용해야 함), " +
                "FTPS explicit/implicit, SFTP, HTTPS(Bearer 토큰을 쓰는 multipart POST). 서버를 SHA-256 지문으로 고정할 수 있습니다 - " +
                "FTPS/HTTPS는 TLS 인증서, SFTP는 호스트 키. 지문이 없으면 SFTP는 첫 접속 시 키를 신뢰하고 known_hosts에 저장합니다. " +
                "비밀번호와 토큰은 settings.json이 아니라 OS 자격 증명 저장소(또는 암호화 파일)에 보관됩니다. 실패한 업로드는 " +
                "outbox(대기열)에 들어가 시작 시와 예약 스캔 후에 재시도되며, 사이드바에 대기 건수가 표시됩니다."),
            new("알림과 알림 운영",
                "알림은 감지된 변화를 웹훅(Slack/Teams/Discord), UDP syslog 서버, 이메일(SMTP, STARTTLS 선택)로 보냅니다. " +
                "'보안 관련 변화만'을 켜면 MAC 변경, 위험 포트, 미승인 장비, 고위험만 보냅니다. 알림은 이력 화면에서 같은 사건당 " +
                "한 건으로 모입니다. 확인하거나 24시간 스누즈하면 재알림이 멈추고, 나중에 다시 열 수 있으며, 재알림 간격(시간)을 " +
                "두면 해결되지 않은 알림을 그 뒤에 다시 보냅니다. 점검 시간대(예: Mon-Fri 22:00-06:00; Sat,Sun)에는 기록만 하고 " +
                "보내지 않습니다. 상태형 알림은 조건이 사라지면 스스로 해결됩니다."),
            new("자산 승인",
                "이력 화면의 인벤토리에는 지금까지 발견된 모든 장비가 있습니다. 아는 장비를 승인하고(승인 당시 MAC이 기억됩니다) " +
                "소유자, 태그, 메모를 지정하세요. '첫 스캔 결과를 모두 승인'은 첫 스캔을 기준선으로 삼습니다. '미승인 장비 알림'을 " +
                "켜면 그 밖의 살아있는 호스트가 알림으로 올라오고, 승인된 IP가 다른 MAC으로 응답하면 MAC 불일치로 표시됩니다. " +
                "IP 리스트의 컨텍스트 메뉴에서도 바로 승인하거나 해제할 수 있습니다."),
            new("취약점 평가와 위험 점수",
                "열린 포트, 서비스 배너, TLS 설정을 오프라인 규칙(취약 버전, 약한 프로토콜, 노출 서비스, TLS 문제, 기본 설정)과 " +
                "비교합니다. 발견 항목마다 심각도(정보, 낮음, 중간, 높음, 심각)가 있고 0~100 위험 점수에 더해집니다. 점수가 40 " +
                "이상이면 행이 빨갛게 표시되고, 자산 정책의 '고위험 기준 점수'가 고위험 알림을 올리는 기준입니다. 발견 항목은 " +
                "호스트 상세 창에 나열됩니다."),
            new("이력·보존·백업",
                "모든 스캔은 SQLite 데이터베이스(history.db)에 기록됩니다. 이력 화면은 최근 스캔과 인벤토리(최초/마지막 발견, " +
                "마지막 모델, OS, MAC, 포트)를 보여줍니다. 백업·지원의 '이력 보존(일)'은 오래된 스캔을 자동으로 정리하고(0 = 무제한) " +
                "이력 화면의 정리 버튼도 같은 일수를 씁니다. 백업 사본은 하루 한 번 만들어지고 최신 N개가 보관됩니다. '지금 백업'은 " +
                "즉시 백업을 만들고, '복원…'은 고른 백업으로 다음 시작 때 데이터베이스를 교체합니다."),
            new("설정 내보내기·가져오기와 진단",
                "'설정 내보내기'는 설정과 대역을 비밀 정보 없이 JSON 파일로 저장하고, '설정 가져오기'는 그 파일을 불러옵니다(언어는 " +
                "재시작 후 적용). '진단 번들 만들기'는 설정, 최근 로그, 환경 정보, 이력 요약을 지원 요청용 zip으로 묶습니다. 설정은 " +
                "저장할 때 검증되어, 잘못된 숫자나 호스트가 있으면 목록으로 보여주고 고칠 때까지 저장하지 않습니다."),
            new("자동 업데이트",
                "설치본은 시작할 때와 N시간마다 GitHub Releases에서 새 버전을 확인하고, '백그라운드로 다운로드'가 켜져 있으면 " +
                "조용히 내려받으며, '앱을 닫을 때 설치'를 켜면 종료 시 자동으로 설치합니다. 아니면 사이드바의 업데이트 버튼이 설치 후 " +
                "재시작합니다. '사전 릴리스(beta) 포함'은 beta 채널을 따릅니다. '지금 확인'은 수동 확인입니다. 설정과 이력은 업데이트 " +
                "후에도 유지됩니다. dotnet run으로 띄운 개발 빌드는 업데이트하지 않습니다."),
            new("명령줄과 서비스",
                "netscan은 같은 엔진을 쓰는 명령줄 스캐너입니다. 대역을 직접 주거나 저장된 설정을 쓰고, 프로필을 고르고, HTML/JSON/PDF " +
                "리포트를 쓰고, 업로드와 알림을 보내며, 이력·자산·알림·설정 내보내기/가져오기·진단 번들을 다룹니다. 위험 포트가 " +
                "발견되면 종료 코드 3으로 끝납니다. netscan-service는 settings.json의 같은 스케줄을 Windows 서비스, systemd 유닛, " +
                "launchd 에이전트로 GUI 없이 실행하는 헤드리스 스케줄러이며, 재시작 후 놓친 실행을 보충합니다."),
            new("자주 묻는 질문",
                "Q. MAC 주소가 자주 비어 있어요.\n" +
                "A. MAC은 같은 서브넷 안에서만 ARP로 알아낼 수 있습니다. 라우터 건너편이나 다른 VLAN의 호스트는 원리상 조회할 수 " +
                "없고(오류가 아님), 스캔하는 PC 자신의 MAC도 표시되지 않습니다. 라우팅된 구간은 게이트웨이 SNMP 테이블이 채워 줄 수 " +
                "있습니다.\n\n" +
                "Q. 응답시간에 'TCP', 'MCAST', 'TABLE'이라고 표시돼요.\n" +
                "A. 해당 호스트가 Ping에는 응답하지 않았지만 대표 TCP 포트로, 멀티캐스트 발견 응답으로, 또는 이웃/SNMP 테이블에서 " +
                "생존이 확인된 경우입니다.\n\n" +
                "Q. Ping 권한이 없다고 나와요.\n" +
                "A. Linux에서는 'sudo setcap cap_net_raw+ep <실행파일>'을 실행하거나 루트로, 다른 시스템에서는 관리자 권한으로 " +
                "실행하세요.\n\n" +
                "Q. 앱 언어는 어떻게 바꾸나요?\n" +
                "A. 설정 화면에서 언어(English/한국어)를 선택하면 재시작 후 적용됩니다."),
        };
    }
}
