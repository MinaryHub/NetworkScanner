using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json.Serialization;
using NetworkScanner.Alerts;
using NetworkScanner.Network;
using NetworkScanner.Upload;

namespace NetworkScanner
{
    // SettingsView(Avalonia)와 CLI 옵션이 채우는 설정값을 담는 순수 데이터 모델.
    // 영속화는 AppSettingsStore가 담당한다.
    public class AppSettingsData
    {
        public bool UseScheduling { get; set; }

        // index 0 => "hr01"(1시) ... index 23 => "hr24"(24시, 즉 자정 0시)
        public bool[] HourEnabled { get; set; } = new bool[24];

        public UploadSettings Upload { get; set; } = new UploadSettings();

        public string SystemName { get; set; } = "";
        public string PortList { get; set; } = "22/80/8080";
        public bool UsePortChecking { get; set; }
        public bool LoadLatestFileOnStartup { get; set; } = true;

        // 연속 모니터링: 켜면 지정한 분(分) 간격마다 자동으로 전체 대역을 재스캔한다.
        public bool ContinuousMonitoring { get; set; }
        public int MonitorIntervalMinutes { get; set; } = 10;

        // UI 언어("en"/"ko"). 기본값 영어. 변경은 재시작 시 반영된다.
        public string Language { get; set; } = Localization.English;

        // 사용자가 드래그로 조절한 컬럼 너비를 열 순서대로 쉼표로 저장한다(예: "90,140,160,...").
        // 비어 있으면 XAML 기본 너비를 사용한다.
        public string IpListColumnWidths { get; set; } = "";
        public string IpRangeColumnWidths { get; set; } = "";

        // 스캔 동작 한계. 동시성과 대역 크기 상한으로 실수로 거대한 대역을 두드리는 일을 막는다.
        public int ScanParallelism { get; set; } = 64;
        public int MaxTargets { get; set; } = 65536;

        // 위험 포트 예외 목록("8080, 10.0.0.5:31337, 10.0.1.0/24:12345"). 승인된 정상 서비스는 경고에서 제외한다.
        public string RiskAllowList { get; set; } = "";

        // 사용 고지(허가된 네트워크만 스캔) 확인 여부. 최초 실행 시 한 번 묻는다.
        public bool UsageNoticeAccepted { get; set; }

        // 알림(변화 감지/위험 포트). 비어 있으면 비활성.
        public NotificationSettings Notifications { get; set; } = new NotificationSettings();

        // 알림 운영(재알림 간격, 점검 시간대)과 자산 승인 정책.
        public AlertSettings Alerts { get; set; } = new AlertSettings();
        public AssetPolicySettings AssetPolicy { get; set; } = new AssetPolicySettings();

        // 심층 발견/핑거프린트(SSDP·mDNS 브라우징, SMB/SSH/HTTP/UDP 프로브, 라우터 SNMP 테이블, 패시브 캡처).
        public DiscoverySettings Discovery { get; set; } = new DiscoverySettings();

        // 식별 프로브(SNMP/mDNS/NetBIOS)와 취약점 평가.
        public IdentitySettings Identity { get; set; } = new IdentitySettings();
        public bool AssessVulnerabilities { get; set; } = true;

        // 스캔 프로필("quick"/"standard"/"thorough").
        public string ScanProfile { get; set; } = "standard";

        // 자동 업데이트(GUI는 Velopack, CLI/서비스는 GitHub 릴리스 압축본).
        public UpdateSettings Update { get; set; } = new UpdateSettings();

        // 이력 보존 일수(0 = 무제한)와 자동 백업 보관 개수.
        public int HistoryRetentionDays { get; set; } = 180;
        public int HistoryBackupsToKeep { get; set; } = 3;

        public bool IsInScheduleHour(int clockHour)
        {
            int label = clockHour == 0 ? 24 : clockHour;
            if (label < 1 || label > 24) return false;
            return HourEnabled[label - 1];
        }

        // 저장/사용 전에 호출해 잘못된 입력을 걸러낸다. 반환된 목록이 비어 있으면 유효하다.
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (MonitorIntervalMinutes < 1 || MonitorIntervalMinutes > 1440)
                errors.Add(Localization.T("settings.invalid.interval"));

            if (ScanParallelism < 1 || ScanParallelism > 512)
                errors.Add(Localization.T("settings.invalid.parallelism"));

            if (UsePortChecking)
            {
                var ports = ProbeExtensions.ParsePorts(PortList);
                if (ports.Count == 0) errors.Add(Localization.T("settings.invalid.portlist"));
            }

            var (_, invalidWindows) = MaintenanceWindow.ParseList(Alerts.MaintenanceWindows);
            if (invalidWindows.Count > 0)
                errors.Add(string.Format(Localization.T("settings.invalid.maintenance"), string.Join("; ", invalidWindows)));
            if (Alerts.RenotifyAfterHours < 0 || Alerts.RenotifyAfterHours > 720)
                errors.Add(Localization.T("settings.invalid.renotify"));
            if (HistoryRetentionDays < 0) errors.Add(Localization.T("settings.invalid.retention"));
            if (Update.CheckIntervalHours < 1 || Update.CheckIntervalHours > 168) errors.Add(Localization.T("settings.invalid.updateinterval"));

            var (_, invalidAllow) = RiskPolicy.ParseAllowList(RiskAllowList);
            if (invalidAllow.Count > 0)
                errors.Add(string.Format(Localization.T("settings.invalid.riskallow"), string.Join(", ", invalidAllow)));

            if (Upload.Enabled)
            {
                if (!IsValidHost(Upload.Host)) errors.Add(Localization.T("settings.invalid.ftphost"));
                if (Upload.Port < 0 || Upload.Port > 65535) errors.Add(Localization.T("settings.invalid.ftpport"));
                if (Upload.Protocol == UploadProtocol.Ftp && !Upload.AllowInsecure)
                    errors.Add(Localization.T("settings.invalid.insecureftp"));
                if (Upload.Protocol == UploadProtocol.Https && string.IsNullOrWhiteSpace(Upload.BearerToken))
                    errors.Add(Localization.T("settings.invalid.token"));
                if (string.IsNullOrWhiteSpace(SystemName)) errors.Add(Localization.T("settings.invalid.systemname"));
            }

            return errors;
        }

        private static bool IsValidHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (IPAddress.TryParse(host, out _)) return true;
            return Uri.CheckHostName(host) is UriHostNameType.Dns;
        }
    }

    public sealed class UpdateSettings
    {
        public bool AutoCheck { get; set; } = true;            // 시작 시 + 주기적으로 새 버전 확인
        public bool AutoDownload { get; set; } = true;         // 찾으면 백그라운드로 내려받기
        public bool AutoApply { get; set; }                    // GUI: 앱 종료 시 자동 설치 / 서비스: 즉시 설치 후 재시작
        public bool IncludePrerelease { get; set; }            // beta 채널(사전 릴리스) 포함
        public int CheckIntervalHours { get; set; } = 6;
        // 릴리스를 읽을 GitHub 저장소("owner/name"). 비우면 기본 저장소. 포크나 사내 미러용.
        public string Repository { get; set; } = "";
    }

    public sealed class AssetPolicySettings
    {
        // 승인되지 않은 장비가 살아있으면 알림(UnapprovedHost).
        public bool AlertOnUnapproved { get; set; }
        // 첫 스캔(인벤토리가 비어 있을 때) 결과를 모두 승인 처리해 기준선으로 삼는다.
        public bool AutoApproveFirstScan { get; set; } = true;
        // 이 점수 이상이면 HighRisk 알림(0 = 끔).
        public int HighRiskThreshold { get; set; } = 40;
    }

    public sealed class DiscoverySettings
    {
        public bool Ssdp { get; set; } = true;              // UPnP M-SEARCH 멀티캐스트
        public bool MdnsBrowse { get; set; } = true;        // Bonjour 서비스 브라우징
        public bool Smb { get; set; } = true;               // SMB2/NTLM 협상(OS 버전·호스트명)
        public bool Ssh { get; set; } = true;               // SSH 배너 → 배포판
        public bool Http { get; set; } = true;              // 웹 페이지/인증서 핑거프린트
        public bool UdpProbes { get; set; } = true;         // DNS/NTP/SSDP/TFTP/SIP
        public bool NeighborTables { get; set; } = true;    // OS ARP/NDP 테이블(IPv6 포함)
        public bool GatewaySnmp { get; set; } = true;       // 기본 게이트웨이의 ARP/FDB/LLDP 테이블(SNMP)
        public string SnmpAgents { get; set; } = "";        // 추가 SNMP 장비 "ip[:community]; ip2"
        public bool ActiveArp { get; set; } = true;         // 능동 ARP(지원 OS·권한일 때만)
        public bool PassiveListener { get; set; }           // 패시브 캡처(libpcap/npcap + 권한 필요)
        public bool MergeHistory { get; set; } = true;      // 이전 스캔의 사실을 낮은 신뢰도로 합침
        public int DiscoveryTimeoutMs { get; set; } = 3000;
        public int ProbeTimeoutMs { get; set; } = 2500;
    }

    public sealed class IdentitySettings
    {
        public bool Snmp { get; set; } = true;
        public string SnmpCommunity { get; set; } = "public";
        public bool Mdns { get; set; } = true;
        public bool NetBios { get; set; } = true;
    }

    public sealed class NotificationSettings
    {
        public bool Enabled { get; set; }
        public bool OnSecurityOnly { get; set; } = true;  // MAC 변경/위험 포트만 알릴지, 모든 변화를 알릴지

        public string WebhookUrl { get; set; } = "";      // Slack/Teams/Discord 등 incoming webhook
        public string SyslogHost { get; set; } = "";      // UDP syslog 수신 서버
        public int SyslogPort { get; set; } = 514;

        public string SmtpHost { get; set; } = "";
        public int SmtpPort { get; set; } = 587;
        public bool SmtpUseStartTls { get; set; } = true;
        public string SmtpUser { get; set; } = "";
        [JsonIgnore] public string SmtpPassword { get; set; } = "";    // ISecretStore에 저장
        public string MailFrom { get; set; } = "";
        public string MailTo { get; set; } = "";          // 쉼표 구분
    }
}
