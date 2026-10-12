using System;
using System.Collections.Generic;
using NetworkScanner.Alerts;
using NetworkScanner.Discovery;
using NetworkScanner.History;
using NetworkScanner.Network;
using NetworkScanner.Platform;
using NetworkScanner.Upload;

namespace NetworkScanner
{
    // 스캔 동작 파라미터. 설정 화면/CLI가 채우며, 기본값은 일반 사무실 LAN 기준이다.
    public sealed class ScanOptions
    {
        public int PingTimeoutMs { get; set; } = 500;
        public int TcpLivenessTimeoutMs { get; set; } = 400;
        public int PortTimeoutMs { get; set; } = 300;
        public int BannerTimeoutMs { get; set; } = 700;
        public int DnsTimeoutMs { get; set; } = 1500;
        public int IdentityTimeoutMs { get; set; } = 1500;
        // 심층 발견: 네트워크 전체 발견(SSDP/mDNS/테이블) 시간과 호스트별 핑거프린트 프로브 시간, 이전 스캔 사실 병합.
        public bool DeepDiscovery { get; set; } = true;
        public int DiscoveryTimeoutMs { get; set; } = 3000;
        public int FactProbeTimeoutMs { get; set; } = 2500;
        public bool MergeHistoryFacts { get; set; } = true;
        // 1단계 응답시간을 보고 타임아웃을 늘리는 적응형 조정(느린 Wi-Fi 세그먼트 누락 감소).
        public bool AdaptiveTimeouts { get; set; } = true;
        // 1단계 무응답 호스트 재시도 횟수(타임아웃 2배)와 ARP 캐시 기반 생존 판정, Unix TTL 측정(ping 1회).
        public int PingRetries { get; set; } = 1;
        public bool ArpLiveness { get; set; } = true;
        public bool MeasureTtl { get; set; } = true;
        public int TlsTimeoutMs { get; set; } = 3000;

        // 대역 전체를 훑는 동시성(호스트 수)과 호스트 한 대 안에서 포트를 동시에 두드리는 수.
        public int Parallelism { get; set; } = 64;
        public int PortParallelism { get; set; } = 16;

        // 실수로 /8 같은 대역을 두드리지 않도록 하는 안전 상한.
        public int MaxTargets { get; set; } = 65536;

        // ICMP 무응답 호스트의 생존 재확인에 쓰는 대표 포트.
        public int[] LivenessProbePorts { get; set; } = { 80, 443, 22, 445, 3389, 8080 };
        // 서비스 배너를 읽을 만한 대표 포트(열려 있는 첫 포트의 배너를 수집).
        public int[] BannerPorts { get; set; } = { 80, 8080, 443, 22, 21, 25, 23, 3306 };

        // 위험 포트 예외(RiskPolicy 형식). 설정 화면/CLI --allow 에서 온다.
        public List<string> RiskAllowList { get; set; } = new();

        // 식별 프로브(SNMP/mDNS/NetBIOS), 배너 수집, 취약점 평가 사용 여부와 추가 검사 포트(정밀 프로필).
        public bool IdentityProbes { get; set; } = true;
        public bool BannerGrab { get; set; } = true;
        public bool AssessVulnerabilities { get; set; } = true;
        public int[] ExtraPorts { get; set; } = Array.Empty<int>();
        public string SnmpCommunity { get; set; } = "public";
        public bool SnmpEnabled { get; set; } = true;
        public bool MdnsEnabled { get; set; } = true;
        public bool NetBiosEnabled { get; set; } = true;
        public ScanProfileKind Profile { get; set; } = ScanProfileKind.Standard;

        // 이력 보존/백업(스캔 후 하루 한 번 수행).
        public int HistoryRetentionDays { get; set; } = 180;
        public int HistoryBackupsToKeep { get; set; } = 3;

        // 자산 승인 정책과 알림 운영 설정(이력 DB가 있을 때만 의미 있다).
        public AssetPolicy AssetPolicy { get; set; } = AssetPolicy.Disabled;
        public bool AutoApproveFirstScan { get; set; } = true;
        public AlertSettings Alerts { get; set; } = new();
        public bool SecurityOnlyAlerts { get; set; } = true;

        public static ScanOptions FromSettings(AppSettingsData s) => ScanProfiles.Apply(new ScanOptions
        {
            Parallelism = Math.Clamp(s.ScanParallelism, 1, 512),
            MaxTargets = Math.Max(1, s.MaxTargets),
            RiskAllowList = RiskPolicy.ParseAllowList(s.RiskAllowList).Valid,
            AssetPolicy = new AssetPolicy(s.AssetPolicy.AlertOnUnapproved, s.AssetPolicy.HighRiskThreshold),
            AutoApproveFirstScan = s.AssetPolicy.AutoApproveFirstScan,
            Alerts = s.Alerts,
            SecurityOnlyAlerts = s.Notifications.OnSecurityOnly,
            AssessVulnerabilities = s.AssessVulnerabilities,
            IdentityProbes = s.Identity.Snmp || s.Identity.Mdns || s.Identity.NetBios,
            SnmpEnabled = s.Identity.Snmp,
            SnmpCommunity = string.IsNullOrWhiteSpace(s.Identity.SnmpCommunity) ? "public" : s.Identity.SnmpCommunity,
            MdnsEnabled = s.Identity.Mdns,
            NetBiosEnabled = s.Identity.NetBios,
            Profile = ScanProfiles.Parse(s.ScanProfile),
            HistoryRetentionDays = Math.Max(0, s.HistoryRetentionDays),
            DiscoveryTimeoutMs = Math.Clamp(s.Discovery.DiscoveryTimeoutMs, 500, 20000),
            FactProbeTimeoutMs = Math.Clamp(s.Discovery.ProbeTimeoutMs, 300, 20000),
            MergeHistoryFacts = s.Discovery.MergeHistory,
            HistoryBackupsToKeep = Math.Max(0, s.HistoryBackupsToKeep),
        }, ScanProfiles.Parse(s.ScanProfile));
    }

    // 엔진이 사용하는 외부 의존성 묶음. 기본값은 실제 네트워크 구현이고, 테스트는 가짜를 끼운다.
    public sealed class ScanServices
    {
        public IPinger Pinger { get; init; } = new IcmpPinger();
        public IPortProber Ports { get; init; } = new TcpPortProber();
        public IArpResolver Arp { get; init; } = ArpResolverFactory.CreateForCurrentOS();
        public IHostNameResolver Dns { get; init; } = new DnsHostNameResolver();
        public ITtlProber Ttl { get; init; } = new PingUtilityTtlProber();
        // 호스트별 핑거프린트 프로브(SMB/SSH/HTTP/UDP)와 네트워크 전체 발견(SSDP/mDNS/라우터 테이블/이웃 테이블).
        // 비어 있으면 엔진은 그 단계를 건너뛴다. 기본 구성은 DiscoveryDefaults가 설정값으로 만든다.
        public IReadOnlyList<IFactProbe> FactProbes { get; init; } = Array.Empty<IFactProbe>();
        public IReadOnlyList<INetworkDiscovery> NetworkDiscoveries { get; init; } = Array.Empty<INetworkDiscovery>();
        // 패시브 캡처가 모아 둔 관측(IP → 사실). 서비스/GUI가 리스너를 소유하고 스냅샷 함수를 넘긴다.
        public Func<IReadOnlyDictionary<string, HostFacts>>? PassiveSnapshot { get; init; }
        // null이면 엔진이 옵션(SNMP/mDNS/NetBIOS 사용 여부, 커뮤니티)에 맞춰 기본 프로브를 만든다. 테스트는 가짜를 끼운다.
        public IIdentityProbe? Identity { get; init; }
        public bool IdentityDisabled { get; init; }
        public UploadService? Uploader { get; init; }
        public ScanHistoryStore? History { get; init; }
        public Func<DateTime> Clock { get; init; } = () => DateTime.Now;

        // 실제 앱용: 업로드 outbox, SQLite 이력, 설정에 따른 심층 발견(프로브/네트워크 발견)까지 연결한다.
        public static ScanServices CreateDefault(AppSettingsData settings, bool withHistory = true, Func<IReadOnlyDictionary<string, HostFacts>>? passiveSnapshot = null)
        {
            ScanServices basic = CreateDefault(withHistory);
            DiscoverySettings d = settings.Discovery;
            string community = string.IsNullOrWhiteSpace(settings.Identity.SnmpCommunity) ? "public" : settings.Identity.SnmpCommunity;
            return new ScanServices
            {
                Uploader = basic.Uploader,
                History = basic.History,
                FactProbes = DiscoveryDefaults.BuildFactProbes(d),
                NetworkDiscoveries = DiscoveryDefaults.BuildNetworkDiscoveries(d, community),
                PassiveSnapshot = passiveSnapshot,
            };
        }

        // 실제 앱용(발견 없이): 업로드 outbox와 SQLite 이력까지 연결한다.
        public static ScanServices CreateDefault(bool withHistory = true)
        {
            ScanHistoryStore? history = null;
            if (withHistory)
            {
                try { history = new ScanHistoryStore(ScanHistoryStore.DefaultPath); }
                catch (Exception ex) { AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.history.failed"), ex.Message)); }
            }
            return new ScanServices
            {
                Uploader = new UploadService(),
                History = history,
            };
        }

        // 테스트용: 네트워크에 전혀 나가지 않는 묶음.
        public static ScanServices CreateOffline(IPinger? pinger = null, IPortProber? ports = null, IArpResolver? arp = null, IHostNameResolver? dns = null)
            => new()
            {
                Pinger = pinger ?? new NeverPinger(),
                Ports = ports ?? new ClosedPortProber(),
                Arp = arp ?? new NullArpResolver(),
                Dns = dns ?? new NoHostNameResolver(),
                IdentityDisabled = true,
                Ttl = new NullTtlProber(),
            };

        private sealed class NeverPinger : IPinger
        {
            public System.Threading.Tasks.Task<PingResult?> PingAsync(System.Net.IPAddress ip, int timeoutMs, System.Threading.CancellationToken ct)
                => System.Threading.Tasks.Task.FromResult<PingResult?>(new PingResult(false, 0, 0, "TimedOut"));
        }

        private sealed class ClosedPortProber : IPortProber
        {
            public System.Threading.Tasks.Task<bool> IsOpenAsync(string ip, int port, int timeoutMs, System.Threading.CancellationToken ct)
                => System.Threading.Tasks.Task.FromResult(false);
            public System.Threading.Tasks.Task<string> GrabBannerAsync(string ip, int port, int timeoutMs, System.Threading.CancellationToken ct)
                => System.Threading.Tasks.Task.FromResult("");
        }

        private sealed class NoHostNameResolver : IHostNameResolver
        {
            public System.Threading.Tasks.Task<string?> ReverseLookupAsync(string ip, int timeoutMs, System.Threading.CancellationToken ct)
                => System.Threading.Tasks.Task.FromResult<string?>(null);
        }
    }
}
