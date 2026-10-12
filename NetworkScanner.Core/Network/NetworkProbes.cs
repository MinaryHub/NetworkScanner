using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Network
{
    // ICMP 응답 요약. 엔진이 System.Net의 PingReply에 직접 묶이지 않도록 한다.
    public readonly record struct PingResult(bool Success, long RoundtripMs, int Ttl, string Status);

    // 네트워크 계층 추상화. 엔진은 이 인터페이스만 보고, 실제 구현(ICMP/TCP/DNS)이나 테스트용 가짜를 끼워 넣는다.
    public interface IPinger
    {
        // 권한 부족 등으로 Ping 자체를 보낼 수 없으면 null.
        Task<PingResult?> PingAsync(IPAddress ip, int timeoutMs, CancellationToken ct);
    }

    public interface IPortProber
    {
        Task<bool> IsOpenAsync(string ip, int port, int timeoutMs, CancellationToken ct);
        Task<string> GrabBannerAsync(string ip, int port, int timeoutMs, CancellationToken ct);
    }

    public interface IHostNameResolver
    {
        Task<string?> ReverseLookupAsync(string ip, int timeoutMs, CancellationToken ct);
    }

    // System.Net.NetworkInformation.Ping 기반 기본 구현.
    public sealed class IcmpPinger : IPinger
    {
        public static Action<string>? OnError { get; set; }

        private static readonly byte[] Buffer = Encoding.ASCII.GetBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        private static int _permissionHintLogged;

        public async Task<PingResult?> PingAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            using var ping = new Ping();
            try
            {
                PingReply reply = await ping.SendPingAsync(ip, TimeSpan.FromMilliseconds(timeoutMs), Buffer,
                    new PingOptions { DontFragment = true }, ct).ConfigureAwait(false);
                return new PingResult(reply.Status == IPStatus.Success, reply.RoundtripTime,
                    OperatingSystem.IsWindows() ? reply.Options?.Ttl ?? 0 : 0, reply.Status.ToString()); // Unix의 Options.Ttl은 송신값이라 버린다
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Report(ex);
                return null;
            }
        }

        private static void Report(Exception ex)
        {
            if (IsPermissionDenied(ex))
            {
                // 대역 스캔 중 매 IP마다 같은 권한 오류가 반복돼도 안내는 한 번만 남긴다.
                if (Interlocked.Exchange(ref _permissionHintLogged, 1) == 0)
                    OnError?.Invoke(string.Format(Localization.T("ping.permissionhint"), ex.Message));
                return;
            }
            OnError?.Invoke(ex.Message);
        }

        private static bool IsPermissionDenied(Exception? ex)
        {
            if (ex == null) return false;
            if (ex is SocketException se && (se.SocketErrorCode == SocketError.AccessDenied || (int)se.SocketErrorCode == 13))
                return true;
            if (IsPermissionDenied(ex.InnerException)) return true;
            return ex.Message.Contains("access", StringComparison.OrdinalIgnoreCase)
                && ex.Message.Contains("denied", StringComparison.OrdinalIgnoreCase);
        }
    }

    // TCP connect 기반 포트 검사와 배너 수집.
    public sealed class TcpPortProber : IPortProber
    {
        public async Task<bool> IsOpenAsync(string ip, int port, int timeoutMs, CancellationToken ct)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                await socket.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
                return socket.Connected;
            }
            catch
            {
                // 연결 거부/타임아웃/취소 등은 모두 "닫힘"으로 간주한다.
                return false;
            }
        }

        // 평문 HTTP 포트. 443/8443 같은 TLS 포트는 평문 HEAD가 통하지 않으므로 여기 두지 않는다(HttpProbe/TlsInspector가 다룬다).
        private static readonly int[] PlainHttpPorts = { 80, 8080, 8000 };
        private static readonly int[] TlsPorts = { 443, 8443 };

        // HTTP 계열은 HEAD 요청을 보내 Server 헤더를, SSH/FTP/SMTP 등은 서버가 먼저 보내는 인사말을 읽는다.
        public async Task<string> GrabBannerAsync(string ip, int port, int timeoutMs, CancellationToken ct)
        {
            if (Array.IndexOf(TlsPorts, port) >= 0) return ""; // TLS 핸드셰이크 없이는 배너가 없다 — 타임아웃만 낭비한다
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                await socket.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);

                bool http = Array.IndexOf(PlainHttpPorts, port) >= 0;
                if (http)
                {
                    byte[] req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n");
                    await socket.SendAsync(req, SocketFlags.None, cts.Token).ConfigureAwait(false);
                }

                var buffer = new byte[512];
                int read = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
                if (read <= 0) return "";

                string text = Encoding.ASCII.GetString(buffer, 0, read);
                return http ? ExtractHttpServer(text) : FirstLine(text);
            }
            catch
            {
                return "";
            }
        }

        internal static string FirstLine(string text)
        {
            int nl = text.IndexOfAny(new[] { '\r', '\n' });
            string line = (nl >= 0 ? text.Substring(0, nl) : text).Trim();
            return line.Length > 80 ? line.Substring(0, 80) : line;
        }

        internal static string ExtractHttpServer(string response)
        {
            foreach (string line in response.Split('\n'))
            {
                if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                    return "HTTP: " + line.Substring(7).Trim();
            }
            // Server 헤더가 없으면 상태 라인(예: "HTTP/1.1 200 OK")이라도 돌려준다.
            return FirstLine(response);
        }
    }

    public sealed class DnsHostNameResolver : IHostNameResolver
    {
        // PTR 레코드가 없는 LAN 호스트에서 오래 걸릴 수 있으므로 타임아웃을 강제한다.
        public async Task<string?> ReverseLookupAsync(string ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                IPHostEntry entry = await Dns.GetHostEntryAsync(ip, ct)
                    .WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), ct).ConfigureAwait(false);
                return entry.HostName;
            }
            catch
            {
                return null;
            }
        }
    }

    // 자주 쓰는 조합 동작. 구현체가 아니라 인터페이스 위에서 동작하므로 테스트에서 가짜와 함께 쓸 수 있다.
    public static class ProbeExtensions
    {
        // 여러 포트를 동시에 검사해 열린 포트를 오름차순 "22/80/" 형식으로 돌려준다.
        public static async Task<List<int>> OpenPortsAsync(this IPortProber prober, string ip, IReadOnlyList<int> ports,
            int timeoutMs, int parallelism, CancellationToken ct)
        {
            var open = new List<int>();
            if (ports.Count == 0) return open;

            using var gate = new SemaphoreSlim(Math.Max(1, parallelism));
            var tasks = new List<Task<(int Port, bool Open)>>(ports.Count);
            foreach (int port in ports)
            {
                tasks.Add(Probe(port));
            }

            foreach (var t in await Task.WhenAll(tasks).ConfigureAwait(false))
            {
                if (t.Open) open.Add(t.Port);
            }
            open.Sort();
            return open;

            async Task<(int, bool)> Probe(int port)
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try { return (port, await prober.IsOpenAsync(ip, port, timeoutMs, ct).ConfigureAwait(false)); }
                finally { gate.Release(); }
            }
        }

        // ICMP에 응답하지 않는 호스트(방화벽 뒤의 서버/프린터/IoT 등)를 놓치지 않도록 대표 포트에 TCP 연결을
        // 시도해 하나라도 열려 있으면 살아있는 것으로 본다. 열린 포트가 나오는 즉시 반환한다.
        public static async Task<bool> IsAliveByTcpAsync(this IPortProber prober, string ip, IReadOnlyList<int> ports,
            int timeoutMs, CancellationToken ct)
        {
            var pending = new List<Task<bool>>(ports.Count);
            foreach (int port in ports) pending.Add(prober.IsOpenAsync(ip, port, timeoutMs, ct));

            while (pending.Count > 0)
            {
                Task<bool> finished = await Task.WhenAny(pending).ConfigureAwait(false);
                pending.Remove(finished);
                if (await finished.ConfigureAwait(false)) return true;
            }
            return false;
        }

        public static string FormatPorts(IEnumerable<int> ports)
        {
            var sb = new StringBuilder();
            foreach (int p in ports) sb.Append(p).Append('/');
            return sb.ToString();
        }

        public static List<int> ParsePorts(string? field)
        {
            var list = new List<int>();
            if (string.IsNullOrEmpty(field)) return list;
            foreach (string token in field.Split(new[] { '/', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                if (int.TryParse(token, out int p) && p >= 1 && p <= 65535 && !list.Contains(p)) list.Add(p);
            return list;
        }
    }
}
