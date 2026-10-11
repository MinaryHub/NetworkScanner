using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Network;

namespace NetworkScanner
{
    // 기본 네트워크 프로브(IcmpPinger/TcpPortProber)에 대한 얇은 정적 진입점. 엔진은 ScanServices를 통해
    // 인터페이스를 쓰고, 이 클래스는 단발 호출(수동 Ping, 테스트)용 편의 API만 남긴다.
    public static class PingTester
    {
        public static Action<string>? OnError
        {
            get => IcmpPinger.OnError;
            set => IcmpPinger.OnError = value;
        }

        public const int DefaultPingTimeoutMs = 500;

        private static readonly IcmpPinger Pinger = new();
        private static readonly TcpPortProber Prober = new();

        public static Task<PingResult?> SendPingAsync(IPAddress ip, int timeoutMs = DefaultPingTimeoutMs, CancellationToken ct = default)
            => Pinger.PingAsync(ip, timeoutMs, ct);

        public static Task<PingResult?> SendPingAsync(string ip, int timeoutMs = DefaultPingTimeoutMs, CancellationToken ct = default)
            => IPAddress.TryParse(ip, out IPAddress? parsed) ? Pinger.PingAsync(parsed, timeoutMs, ct) : Task.FromResult<PingResult?>(null);

        public static Task<bool> CheckPortAsync(string ip, int port, int timeoutMs = 300, CancellationToken ct = default)
            => Prober.IsOpenAsync(ip, port, timeoutMs, ct);

        public static Task<bool> IsAliveByTcpAsync(int[] ports, string ip, int timeoutMs = 400, CancellationToken ct = default)
            => Prober.IsAliveByTcpAsync(ip, ports, timeoutMs, ct);

        public static Task<List<int>> OpenPortsAsync(string ip, IReadOnlyList<int> ports, int timeoutMs = 300, int parallelism = 16, CancellationToken ct = default)
            => Prober.OpenPortsAsync(ip, ports, timeoutMs, parallelism, ct);

        public static Task<string> GrabBannerAsync(string ip, int port, int timeoutMs = 700, CancellationToken ct = default)
            => Prober.GrabBannerAsync(ip, port, timeoutMs, ct);
    }
}
