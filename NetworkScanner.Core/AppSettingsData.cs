using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json.Serialization;
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

        // 이전 코드와의 호환용 별칭. 새 코드는 Upload.*를 쓴다.
        [JsonIgnore] public bool UseFTP { get => Upload.Enabled; set => Upload.Enabled = value; }
        [JsonIgnore] public string FtpIp { get => Upload.Host; set => Upload.Host = value; }
        [JsonIgnore] public string FtpId { get => Upload.User; set => Upload.User = value; }
        [JsonIgnore] public string FtpPassword { get => Upload.Password; set => Upload.Password = value; }
        [JsonIgnore] public string FtpPort
        {
            get => Upload.Port > 0 ? Upload.Port.ToString() : "";
            set => Upload.Port = int.TryParse(value, out int p) ? p : 0;
        }

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

        // 알림(변화 감지/위험 포트). 비어 있으면 비활성.
        public NotificationSettings Notifications { get; set; } = new NotificationSettings();

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

            if (ContinuousMonitoring && UseScheduling)
            {
                // 둘 다 켜도 동작은 하지만 의도치 않은 중복 스캔이므로 경고 수준으로 알린다.
            }

            return errors;
        }

        public static bool IsValidHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (IPAddress.TryParse(host, out _)) return true;
            return Uri.CheckHostName(host) is UriHostNameType.Dns;
        }
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

        [JsonIgnore] public bool AnyChannelConfigured =>
            !string.IsNullOrWhiteSpace(WebhookUrl) || !string.IsNullOrWhiteSpace(SyslogHost)
            || (!string.IsNullOrWhiteSpace(SmtpHost) && !string.IsNullOrWhiteSpace(MailTo));
    }
}
