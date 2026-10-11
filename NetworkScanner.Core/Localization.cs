using System.Collections.Generic;

namespace NetworkScanner
{
    // 간단한 키 기반 다국어 지원. 기본 언어는 영어("en")이며 한국어("ko")를 지원한다.
    // 언어는 앱 시작 시 설정에서 읽어 고정되고(전환은 재시작 시 반영), UI/코드/리포트가 T(key)로 문자열을 얻는다.
    public static class Localization
    {
        public const string English = "en";
        public const string Korean = "ko";

        // 현재 언어. 기본값은 영어.
        public static string Current { get; set; } = English;

        public static bool IsKorean => Current == Korean;

        // key -> (en, ko)
        private static readonly Dictionary<string, (string En, string Ko)> Table = new()
        {
            // 공통/네비게이션
            ["app.title"] = ("Network Scanner", "Network Scanner"),
            ["nav.iplist"] = ("IP List", "IP 리스트"),
            ["nav.settings"] = ("Settings", "설정"),
            ["nav.portinfo"] = ("Ref. Ports", "참고. 포트정보"),
            ["nav.guide"] = ("User Guide", "사용 설명서"),
            ["guide.title"] = ("User Guide", "사용 설명서"),

            // IP 리스트 화면
            ["iplist.title"] = ("IP List", "IP List"),
            ["btn.new"] = ("New", "새로 만들기"),
            ["btn.open"] = ("Open", "파일 열기"),
            ["btn.save"] = ("Save", "파일 저장"),
            ["btn.report"] = ("Report (HTML/JSON)", "리포트(HTML/JSON)"),
            ["btn.scan"] = ("Scan", "스캔"),
            ["btn.scanning"] = ("Scanning...", "스캔 중..."),
            ["btn.cancel"] = ("Cancel", "취소"),
            ["label.search"] = ("Search:", "검색:"),
            ["search.watermark"] = ("IP / name / port / MAC / vendor / note", "IP/이름/포트/Mac/Vendor/비고"),
            ["filter.aliveonly"] = ("Alive only", "살아있는 것만"),
            ["legend.up"] = ("Up", "정상"),
            ["legend.warn"] = ("Warning (risky port)", "주의(위험포트)"),
            ["legend.down"] = ("Down", "없음"),

            // 상태 텍스트(그리드/리포트 공용)
            ["status.up"] = ("Up", "정상"),
            ["status.warn"] = ("Warning", "주의"),
            ["status.down"] = ("Down", "없음"),

            // 컬럼 헤더
            ["col.status"] = ("Status", "상태"),
            ["col.ip"] = ("IP", "IP"),
            ["col.name"] = ("Name", "이름"),
            ["col.type"] = ("Type", "종류"),
            ["col.os"] = ("OS (guess)", "OS추정"),
            ["col.ports"] = ("Open Ports", "열린 Port"),
            ["col.service"] = ("Service", "서비스"),
            ["col.mac"] = ("MAC Address", "Mac Address"),
            ["col.vendor"] = ("Vendor", "Vendor"),
            ["col.rtt"] = ("RTT (ms)", "Round Time(ms)"),
            ["col.note"] = ("Note", "비고"),
            ["col.created"] = ("Created", "생성일"),

            // 컨텍스트 메뉴
            ["menu.ping"] = ("Ping", "Ping 보내기"),
            ["menu.checkport"] = ("Check configured ports", "설정된 Port만 검색"),
            ["menu.checkreserved"] = ("Check all reserved ports", "예약 Port 전체 검색"),
            ["menu.checkprohibit"] = ("Check all risky ports", "위험 Port 전체 검색"),
            ["menu.wol"] = ("Wake-on-LAN", "Wake-on-LAN (원격 켜기)"),
            ["menu.remove"] = ("Remove", "삭제"),

            // 설정 화면
            ["settings.title"] = ("Settings", "설정 화면"),
            ["settings.save"] = ("Save settings", "설정 저장"),
            ["settings.iprange"] = ("IP scan ranges", "IP 검색 범위"),
            ["settings.startip"] = ("Start IP", "시작 IP"),
            ["settings.endip"] = ("End IP", "종료 IP"),
            ["settings.desc"] = ("Description", "설명"),
            ["settings.addrange"] = ("Add range", "대역 추가"),
            ["settings.removerange"] = ("Remove range", "대역 삭제"),
            ["settings.ports"] = ("Ports to scan", "검색할 Port"),
            ["settings.useportcheck"] = ("Enable port scan", "Port 검색 사용"),
            ["settings.portno"] = ("Port numbers", "Port 번호"),
            ["settings.scheduling"] = ("Scheduling", "스케줄링"),
            ["settings.usescheduling"] = ("Enable scheduling", "스케줄링 사용"),
            ["settings.filelocation"] = ("File save location", "파일저장위치"),
            ["settings.ftpsave"] = ("FTP upload", "FTP 저장"),
            ["settings.useftp"] = ("Enable FTP upload", "FTP 저장 사용"),
            ["settings.general"] = ("General", "일반"),
            ["settings.systemname"] = ("System name", "시스템 이름"),
            ["settings.loadlatest"] = ("Load latest file on startup", "시작시 최근 기록 부르기"),
            ["settings.continuous"] = ("Continuous monitoring", "연속 모니터링"),
            ["settings.interval"] = ("min interval", "분 간격"),
            ["settings.language"] = ("Language", "언어"),
            ["settings.lang.restart"] = ("(applies after restart)", "(재시작 후 적용)"),

            // 메시지/대화상자
            ["msg.deleteall"] = ("Delete all items?", "리스트를 모두 삭제할까요?"),
            ["msg.delete"] = ("Delete", "삭제"),
            ["dlg.confirm"] = ("Confirm", "확인"),
            ["msg.noresult.report"] = ("No results to export.", "리포트로 저장할 결과가 없습니다."),
            ["msg.report.saved.html"] = ("HTML report saved.", "HTML 리포트를 저장했습니다."),
            ["msg.report.saved.json"] = ("JSON report saved.", "JSON 리포트를 저장했습니다."),
            ["msg.wol.nomac"] = ("No MAC address; cannot send Wake-on-LAN.", "MAC 주소가 없어 Wake-on-LAN을 보낼 수 없습니다."),
            ["msg.wol.sent"] = ("Sent Wake-on-LAN magic packet:", "Wake-on-LAN 매직 패킷을 보냈습니다:"),
            ["msg.wol.failed"] = ("Failed to send Wake-on-LAN.", "Wake-on-LAN 전송에 실패했습니다."),
            ["msg.cidr.invalid"] = ("Invalid CIDR (e.g. 192.168.1.0/24)", "CIDR 형식이 올바르지 않습니다 (예: 192.168.1.0/24)"),
            ["msg.startip.invalid"] = ("Invalid start IP (or CIDR: 192.168.1.0/24)", "시작 IP 값 이상 (또는 CIDR 형식: 192.168.1.0/24)"),
            ["msg.endip.invalid"] = ("Invalid end IP", "종료 IP 값 이상"),
            ["msg.range.duplicate"] = ("This range is already registered.", "이미 등록된 대역입니다."),
            ["msg.range.saved"] = ("Saved IP scan range file.", "IP 검색 대역 파일을 저장하였습니다."),
            ["msg.settings.saved"] = ("Saved settings file.", "설정 파일을 저장하였습니다."),

            // 스캔 진행/결과 (ScanEngine)
            ["scan.norange"] = ("No IP scan range configured. Add one in Settings.", "설정된 IP 검색 대역이 없습니다. 설정 화면에서 대역을 추가해주세요."),
            ["scan.phase1.start"] = ("[1/2] Host discovery started", "[1/2] 호스트 검색 시작"),
            ["scan.phase1.progress"] = ("[1/2] Discovering", "[1/2] 호스트 검색"),
            ["scan.phase2.start"] = ("[2/2] Detail lookup started", "[2/2] 상세 조회 시작"),
            ["scan.phase2.progress"] = ("[2/2] Detail", "[2/2] 상세 조회"),
            ["scan.cancelled"] = ("Scan cancelled.", "스캔이 취소되었습니다."),
            ["scan.completed"] = ("Scan complete.", "스캔을 완료했습니다."),
            ["scan.alivecount"] = ("alive hosts", "살아있는 호스트"),
            ["scan.alreadyscanning"] = ("Already scanning.", "이미 스캐닝 중입니다."),
            ["scan.cancelrequested"] = ("Requested scan cancellation.", "스캔 취소를 요청했습니다."),

            // 변화 감지
            ["change.detected"] = ("changes detected", "건 감지"),
            ["change.securityalert"] = ("security alerts", "보안 경고"),
            ["change.dialogtitle"] = ("Security alert - scan changes", "보안 경고 - 스캔 변화 감지"),
            ["change.newhost"] = ("New/returning host:", "신규/재접속 호스트:"),
            ["change.offline"] = ("Went offline:", "오프라인 전환:"),
            ["change.macchanged"] = ("⚠ MAC changed:", "⚠ MAC 변경:"),
            ["change.newport"] = ("New open port:", "새 포트 열림:"),
            ["change.prohibited"] = ("⚠ Risky port found:", "⚠ 위험 포트 발견:"),
            ["change.newdevice"] = ("new device", "새 장비"),
            ["change.reconnect"] = ("reconnected", "재접속"),
            ["change.noresponse"] = ("no response", "응답 없음"),

            // 장비 종류 분류(DeviceClassifier)
            ["dev.apple"] = ("Apple device", "Apple 기기"),
            ["dev.samsung"] = ("Samsung device", "Samsung 기기"),
            ["dev.lg"] = ("LG device", "LG 기기"),
            ["dev.raspberrypi"] = ("Raspberry Pi", "라즈베리파이"),
            ["dev.pc"] = ("PC", "PC"),
            ["dev.pclaptop"] = ("PC/Laptop", "PC/노트북"),
            ["dev.pcnet"] = ("PC/Network", "PC/네트워크"),
            ["dev.printerpc"] = ("Printer/PC", "프린터/PC"),
            ["dev.printer"] = ("Printer", "프린터"),
            ["dev.network"] = ("Network device", "네트워크 장비"),
            ["dev.cctv"] = ("CCTV/IP camera", "CCTV/IP카메라"),
            ["dev.iot"] = ("IoT device", "IoT 장치"),
            ["dev.iotmedia"] = ("IoT/Media", "IoT/미디어"),
            ["dev.media"] = ("Media device", "미디어 기기"),
            ["dev.windowspc"] = ("Windows PC", "Windows PC"),
            ["dev.winshare"] = ("Windows/File share", "Windows/파일공유"),
            ["dev.server"] = ("Server/Linux", "서버/리눅스"),
            ["dev.web"] = ("Web service device", "웹 서비스 장비"),

            // 업데이트
            ["update.button"] = ("Update", "업데이트"),
            ["update.available"] = ("New version {0} is available. Click to install.", "새 버전 {0}이(가) 있습니다. 클릭하면 설치합니다."),
            ["update.downloading"] = ("Downloading...", "다운로드 중..."),
            ["update.failed"] = ("Update failed", "업데이트 실패"),


            // Core 공통 메시지(엔진/저장소/리포트). {0} 자리에는 파일명·IP·오류 메시지가 들어간다.
            ["msg.file.loadfailed"] = ("Could not load file: {0}", "파일을 불러오지 못했습니다: {0}"),
            ["msg.file.nothingtosave"] = ("Nothing to save.", "저장할 아이템이 없습니다"),
            ["msg.file.saved"] = ("Saved file: {0}", "파일을 저장했습니다. File Name : {0}"),
            ["msg.file.savefailed"] = ("Error while saving file: {0}", "파일 저장 중 오류가 발생했습니다: {0}"),
            ["msg.report.saved"] = ("Saved report: {0}", "리포트를 저장했습니다. File Name : {0}"),
            ["msg.report.savefailed"] = ("Automatic report save failed: {0}", "자동 리포트 저장 실패: {0}"),
            ["msg.parse.skipped"] = ("Failed to parse {0} (line skipped): {1}", "{0} 파싱 실패(줄 건너뜀): {1}"),
            ["msg.store.loadfailed"] = ("Failed to load {0}: {1}", "{0} 로드 실패: {1}"),
            ["msg.store.savefailed"] = ("Failed to save {0}: {1}", "{0} 저장 실패: {1}"),
            ["msg.upload.failed"] = ("Upload failed ({0}): {1}", "업로드 실패({0}): {1}"),
            ["msg.upload.queued"] = ("Upload failed; queued for retry: {0}", "업로드에 실패해 재시도 대기열에 넣었습니다: {0}"),
            ["msg.upload.done"] = ("Uploaded: {0}", "업로드 완료: {0}"),
            ["msg.history.failed"] = ("Failed to record scan history: {0}", "스캔 이력 기록 실패: {0}"),
            ["scan.invalidrange"] = ("Skipping invalid IP range: {0} ~ {1}", "잘못된 IP 대역을 건너뜁니다: {0} ~ {1}"),
            ["scan.toomanytargets"] = ("Range too large ({0} addresses; limit {1}). Narrow the range or raise the limit in Settings.", "대역이 너무 큽니다({0}개; 상한 {1}). 대역을 줄이거나 설정에서 상한을 높이세요."),
            ["ping.manual"] = ("Manual ping to {0}: {1}", "수동으로 {0}에 Ping을 보냈습니다. 결과 : {1}"),
            ["ping.failed"] = ("failed (permission or other error; see log)", "실패(권한 등 오류, 로그 확인)"),
            ["ping.permissionhint"] = ("ICMP ping is not permitted, so scan results may be incomplete. On Linux run 'sudo setcap cap_net_raw+ep <executable>' or run as root/administrator. (original error: {0})",
                                       "ICMP Ping 권한이 없어 이후 스캔 결과가 부정확할 수 있습니다. Linux에서는 'sudo setcap cap_net_raw+ep <실행파일 경로>' 실행 후 다시 시도하거나 관리자/루트 권한으로 실행하세요. (원본 오류: {0})"),
            ["portcheck.start.reserved"] = ("Checking all reserved ports on {0}...", " {0}으로 예약된 포트 전부 검색을 시작합니다."),
            ["portcheck.start.prohibit"] = ("Checking all risky ports on {0}...", " {0}으로 금지된 포트 전부 검색을 시작합니다."),
            ["portcheck.start.user"] = ("Checking configured ports on {0}...", " {0}으로 사용자 포트 전부 검색을 시작합니다."),
            ["portcheck.progress"] = ("({0}/{1}) IP: {2}, port: {3}", "({0}/{1})IP: {2}, 검색 Port: {3}"),
            ["portcheck.done"] = ("Port check on {0} finished. Open: {1}", " {0} 포트 검색을 완료했습니다. 결과 : {1}"),
            ["portcheck.unknownhost"] = ("{0} is not in the list.", "{0}은(는) 목록에 없습니다."),
            ["local.autodetected"] = ("Auto-detected local subnet ({0})", "자동 감지된 로컬 대역 ({0})"),
            ["wol.invalidmac"] = ("Invalid MAC address format: {0}", "MAC 주소 형식이 올바르지 않습니다: {0}"),
            ["wol.sendfailed"] = ("Wake-on-LAN send failed: {0}", "Wake-on-LAN 전송 실패: {0}"),
            ["secret.unavailable"] = ("No OS credential store is available; secrets are kept in an encrypted file under the user data folder.", "OS 자격 증명 저장소를 사용할 수 없어 비밀번호를 사용자 데이터 폴더의 암호화 파일에 보관합니다."),

            // 리포트(HTML)
            ["report.title"] = ("NetworkScanner scan report", "NetworkScanner 스캔 리포트"),
            ["report.system"] = ("System", "시스템"),
            ["report.generated"] = ("Generated", "생성"),
            ["report.total"] = ("Total", "전체"),
            ["report.alive"] = ("Up", "정상"),
            ["report.prohibited"] = ("Risky ports", "위험 포트"),

            // 설정 검증
            ["settings.invalid.interval"] = ("Monitoring interval must be 1–1440 minutes.", "모니터링 간격은 1~1440분이어야 합니다."),
            ["settings.invalid.parallelism"] = ("Scan parallelism must be 1–512.", "스캔 동시성은 1~512여야 합니다."),
            ["settings.invalid.portlist"] = ("Port list is empty or invalid (e.g. 22/80/443).", "포트 목록이 비어 있거나 잘못되었습니다(예: 22/80/443)."),
            ["settings.invalid.ftphost"] = ("Upload host is not a valid IP address or host name.", "업로드 호스트가 올바른 IP/호스트명이 아닙니다."),
            ["settings.invalid.ftpport"] = ("Upload port must be 1–65535 (or blank for the default).", "업로드 포트는 1~65535(또는 기본값은 비워 둠)여야 합니다."),
            ["settings.invalid.insecureftp"] = ("Plain FTP sends credentials unencrypted. Choose FTPS/SFTP/HTTPS or explicitly allow insecure FTP.", "평문 FTP는 자격 증명이 암호화되지 않습니다. FTPS/SFTP/HTTPS를 선택하거나 비보안 FTP를 명시적으로 허용하세요."),
            ["settings.invalid.token"] = ("HTTPS upload requires an access token.", "HTTPS 업로드에는 접근 토큰이 필요합니다."),
            ["settings.invalid.systemname"] = ("System name is required when upload is enabled.", "업로드를 사용하려면 시스템 이름이 필요합니다."),
            ["settings.invalid.title"] = ("Settings not saved - please fix:", "설정이 저장되지 않았습니다 - 다음을 수정하세요:"),
            ["settings.upload"] = ("Result upload", "결과 업로드"),
            ["settings.useupload"] = ("Enable result upload", "결과 업로드 사용"),
            ["settings.protocol"] = ("Protocol", "프로토콜"),
            ["settings.remotedir"] = ("Remote dir", "원격 경로"),
            ["settings.fingerprint"] = ("Fingerprint (SHA-256)", "지문(SHA-256)"),
            ["settings.token"] = ("Token", "토큰"),
            ["settings.allowinsecure"] = ("Allow plain FTP", "평문 FTP 허용"),
            ["settings.notifications"] = ("Notifications", "알림"),
            ["settings.usenotify"] = ("Enable notifications", "알림 사용"),
            ["settings.securityonly"] = ("Security changes only", "보안 관련 변화만"),
            ["settings.webhook"] = ("Webhook URL", "웹훅 URL"),
            ["settings.syslog"] = ("Syslog host", "Syslog 호스트"),
            ["settings.smtp"] = ("SMTP host", "SMTP 호스트"),
            ["settings.mailfrom"] = ("From", "보내는 주소"),
            ["settings.mailto"] = ("To", "받는 주소"),
            ["settings.scanlimits"] = ("Scan limits", "스캔 한계"),
            ["settings.parallelism"] = ("Parallelism", "동시성"),
            ["settings.maxtargets"] = ("Max addresses", "최대 주소 수"),
            ["settings.history"] = ("History", "이력"),
            ["settings.outbox"] = ("Pending uploads", "대기 중 업로드"),
            ["settings.riskallow"] = ("Risky-port exceptions", "위험 포트 예외"),
            ["settings.riskallow.hint"] = ("e.g. 8080, 10.0.0.5:31337, 10.0.1.0/24:12345", "예: 8080, 10.0.0.5:31337, 10.0.1.0/24:12345"),
            ["settings.invalid.riskallow"] = ("Invalid risky-port exception entries: {0}", "위험 포트 예외 항목이 잘못되었습니다: {0}"),
            ["notice.title"] = ("Before you scan", "스캔하기 전에"),
            ["notice.body"] = ("Only scan networks you own or are explicitly authorized to scan. Port scanning other people's systems may be illegal in your jurisdiction. Scan results and uploaded reports may contain sensitive inventory data - protect them accordingly.",
                               "본인이 소유했거나 명시적으로 허가받은 네트워크만 스캔하세요. 타인의 시스템을 포트 스캔하는 것은 법적 문제가 될 수 있습니다. 스캔 결과와 업로드된 리포트에는 민감한 자산 정보가 포함될 수 있으니 적절히 보호하세요."),
            ["notice.accept"] = ("I understand", "확인했습니다"),
            ["tile.total"] = ("Addresses", "전체 주소"),
            ["tile.shown"] = ("Shown", "표시 중"),
            ["filter.riskonly"] = ("Risky only", "위험만"),
            ["app.crash"] = ("An unexpected error occurred. Details were written to the log folder:", "예기치 않은 오류가 발생했습니다. 자세한 내용은 로그 폴더에 기록되었습니다:"),

            // 참조 포트 정보 화면
            ["portinfo.title"] = ("(Reference) Common port numbers", "(참조) 주요 포트 번호"),
            ["portinfo.reserved"] = ("◎ Reserved ports", "◎ 예약 Port"),
            ["portinfo.backdoor"] = ("◎ Ports commonly used by backdoors and trojans", "◎ 백도어와 트로이 목마가 자주 사용하는 포트"),

            // 설정 화면 - 업로드/알림/한계 상자의 세부 라벨
            ["settings.host"] = ("Host", "호스트"),
            ["settings.port"] = ("Port", "포트"),
            ["settings.port.default"] = ("(blank = default)", "(비우면 기본값)"),
            ["settings.user"] = ("User", "사용자"),
            ["settings.password"] = ("Password", "비밀번호"),
            ["settings.syslogport"] = ("Syslog port", "Syslog 포트"),
            ["settings.smtpport"] = ("SMTP port", "SMTP 포트"),
            ["settings.starttls"] = ("STARTTLS", "STARTTLS"),
            ["settings.smtpuser"] = ("SMTP user", "SMTP 사용자"),
            ["settings.smtppassword"] = ("SMTP password", "SMTP 비밀번호"),
            ["settings.token.https"] = ("(HTTPS only)", "(HTTPS 전용)"),
            ["msg.notify.failed"] = ("Notification failed: {0}", "알림 전송 실패: {0}"),
            ["msg.notify.sent"] = ("Notification sent to {0} channel(s).", "{0}개 채널로 알림을 보냈습니다."),
            ["msg.outbox.flushed"] = ("Sent {0} pending upload(s).", "대기 중이던 업로드 {0}건을 보냈습니다."),

            // 이력 화면
            ["nav.history"] = ("History", "이력"),
            ["history.title"] = ("Scan history", "스캔 이력"),
            ["history.scans"] = ("Recent scans", "최근 스캔"),
            ["history.inventory"] = ("Host inventory", "호스트 인벤토리"),
            ["history.refresh"] = ("Refresh", "새로 고침"),
            ["history.prune"] = ("Prune older than 90 days", "90일 지난 이력 삭제"),
            ["history.prune.confirm"] = ("Delete all scans older than 90 days? This cannot be undone.", "90일이 지난 스캔 이력을 모두 삭제할까요? 되돌릴 수 없습니다."),
            ["history.pruned"] = ("Deleted {0} scan(s).", "스캔 {0}건을 삭제했습니다."),
            ["history.unavailable"] = ("Scan history is unavailable (database could not be opened; see log).", "스캔 이력을 사용할 수 없습니다(데이터베이스를 열지 못했습니다. 로그를 확인하세요)."),
            ["history.loadfailed"] = ("Failed to read history: {0}", "이력을 읽지 못했습니다: {0}"),
            ["history.col.started"] = ("Started", "시작"),
            ["history.col.finished"] = ("Finished", "종료"),
            ["history.col.system"] = ("System", "시스템"),
            ["history.col.total"] = ("Total", "전체"),
            ["history.col.alive"] = ("Alive", "정상"),
            ["history.col.prohibited"] = ("Risky", "위험"),
            ["history.col.scheduled"] = ("Scheduled", "예약"),
            ["history.col.ip"] = ("IP", "IP"),
            ["history.col.firstseen"] = ("First seen", "최초 발견"),
            ["history.col.lastseen"] = ("Last seen", "마지막 발견"),
            ["history.col.lastalive"] = ("Last alive", "마지막 응답"),
            ["history.col.name"] = ("Last name", "마지막 이름"),
            ["history.col.mac"] = ("Last MAC", "마지막 MAC"),
            ["history.col.vendor"] = ("Last vendor", "마지막 Vendor"),
            ["history.col.ports"] = ("Last ports", "마지막 포트"),
            ["history.col.seencount"] = ("Seen", "발견 횟수"),
        };

        public static string T(string key)
        {
            if (Table.TryGetValue(key, out var pair))
                return IsKorean ? pair.Ko : pair.En;
            return key; // 키가 없으면 키 자체를 반환(누락을 눈에 띄게)
        }
    }
}
