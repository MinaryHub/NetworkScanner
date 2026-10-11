using System;
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

        // 대역 전체를 훑는 동시성(호스트 수)과 호스트 한 대 안에서 포트를 동시에 두드리는 수.
        public int Parallelism { get; set; } = 64;
        public int PortParallelism { get; set; } = 16;

        // 실수로 /8 같은 대역을 두드리지 않도록 하는 안전 상한.
        public int MaxTargets { get; set; } = 65536;

        // ICMP 무응답 호스트의 생존 재확인에 쓰는 대표 포트.
        public int[] LivenessProbePorts { get; set; } = { 80, 443, 22, 445, 3389, 8080 };
        // 서비스 배너를 읽을 만한 대표 포트(열려 있는 첫 포트의 배너를 수집).
        public int[] BannerPorts { get; set; } = { 80, 8080, 443, 22, 21, 25, 23, 3306 };

        public static ScanOptions FromSettings(AppSettingsData s) => new()
        {
            Parallelism = Math.Clamp(s.ScanParallelism, 1, 512),
            MaxTargets = Math.Max(1, s.MaxTargets),
        };
    }

    // 엔진이 사용하는 외부 의존성 묶음. 기본값은 실제 네트워크 구현이고, 테스트는 가짜를 끼운다.
    public sealed class ScanServices
    {
        public IPinger Pinger { get; init; } = new IcmpPinger();
        public IPortProber Ports { get; init; } = new TcpPortProber();
        public IArpResolver Arp { get; init; } = ArpResolverFactory.CreateForCurrentOS();
        public IHostNameResolver Dns { get; init; } = new DnsHostNameResolver();
        public UploadService? Uploader { get; init; }
        public ScanHistoryStore? History { get; init; }
        public Func<DateTime> Clock { get; init; } = () => DateTime.Now;

        // 실제 앱용: 업로드 outbox와 SQLite 이력까지 연결한다.
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
