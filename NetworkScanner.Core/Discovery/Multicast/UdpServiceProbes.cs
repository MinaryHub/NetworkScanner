using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Multicast
{
    // 데이터그램 하나로 서비스 존재를 확인하는 UDP 프로브 묶음(DNS/NTP/SSDP 유니캐스트/TFTP/SIP).
    // 각 프로브는 자기 포트가 openPorts에 있거나, openPorts에 -1(알 수 없음 → 일단 시도)이 있을 때만 실행된다.
    public static class UdpServiceProbes
    {
        public const string Source = "UDP";
        // "열린 포트를 모른다"는 뜻의 표지 값
        public const int UnknownPortsSentinel = -1;
        public static readonly int[] UdpPorts = { 53, 123, 1900, 69, 5060 };

        public static IReadOnlyList<IFactProbe> CreateAll() => new IFactProbe[]
        {
            new DnsProbe(), new NtpProbe(), new SsdpUnicastProbe(), new TftpProbe(), new SipProbe(),
        };

        public static bool ShouldRun(IReadOnlyList<int> openPorts, int port)
            => openPorts != null && (openPorts.Contains(port) || openPorts.Contains(UnknownPortsSentinel));

        internal static readonly IReadOnlyList<Fact> Empty = Array.Empty<Fact>();
    }

    // 53/udp: version.bind CH TXT와 example.com A 질의를 각각 한 번 보낸다. 어느 쪽이든 응답(REFUSED 포함)이 오면 DNS 서버다.
    public sealed class DnsProbe : IFactProbe
    {
        public const int DefaultPort = 53;
        private readonly int _port;
        public DnsProbe() : this(DefaultPort) { }
        internal DnsProbe(int port) => _port = port;
        public string Name => "DNS";

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (!UdpServiceProbes.ShouldRun(openPorts, DefaultPort) || !IPAddress.TryParse(ip, out IPAddress? addr)) return UdpServiceProbes.Empty;
                ushort idVersion = (ushort)Random.Shared.Next(1, ushort.MaxValue);
                ushort idA = (ushort)Random.Shared.Next(1, ushort.MaxValue);
                byte[] qVersion = DnsCodec.BuildQuery(idVersion, "version.bind", DnsCodec.TypeTxt, 3 /* CH */);
                byte[] qA = DnsCodec.BuildQuery(idA, "example.com", DnsCodec.TypeA, DnsCodec.ClassIn);

                Task<byte[]?> tVersion = UdpExchange.SendReceiveAsync(addr, _port, qVersion, timeoutMs, 1, d => IsReply(d, idVersion), ct);
                Task<byte[]?> tA = UdpExchange.SendReceiveAsync(addr, _port, qA, timeoutMs, 1, d => IsReply(d, idA), ct);
                await Task.WhenAll(tVersion, tA).ConfigureAwait(false);
                return FactsFromReplies(ip, tVersion.Result, tA.Result);
            }
            catch
            {
                return UdpServiceProbes.Empty;
            }
        }

        private static bool IsReply(byte[] data, ushort id)
            => DnsCodec.TryParseResponse(data, out DnsCodec.Response r) && r.IsResponse && r.Id == id;

        internal static IReadOnlyList<Fact> FactsFromReplies(string ip, byte[]? versionReply, byte[]? aReply)
        {
            if (versionReply == null && aReply == null) return UdpServiceProbes.Empty;
            var hf = new HostFacts(ip);
            string? version = null;
            if (versionReply != null && DnsCodec.TryParseResponse(versionReply, out DnsCodec.Response vr))
            {
                version = vr.Answers.FirstOrDefault(a => a.Type == DnsCodec.TypeTxt && a.Data.Length > 0)?.Data;
            }
            hf.Add(FactFields.Service, version != null ? $"DNS server ({version})" : "DNS server", UdpServiceProbes.Source, Confidence.Medium);
            if (version != null) hf.AddRange(OsHintFromVersion(version));

            byte[]? any = aReply ?? versionReply;
            if (any != null && DnsCodec.TryParseResponse(any, out DnsCodec.Response r))
            {
                bool ra = (r.Flags & 0x0080) != 0;
                int rcode = r.Flags & 0x000F;
                hf.Add(FactFields.Description, ra ? "DNS: recursion available" : rcode == 5 ? "DNS: query refused" : "DNS: authoritative only", UdpServiceProbes.Source, Confidence.Low);
            }
            return hf.All;
        }

        private static IEnumerable<Fact> OsHintFromVersion(string version)
        {
            string v = version.ToLowerInvariant();
            if (v.Contains("microsoft")) yield return new Fact(FactFields.Os, "Windows", UdpServiceProbes.Source, Confidence.Low);
            else if (v.Contains("dnsmasq") || v.Contains("bind") || v.Contains("unbound") || v.Contains("powerdns") || v.Contains("knot"))
                yield return new Fact(FactFields.Os, "Linux", UdpServiceProbes.Source, Confidence.Low);
        }
    }

    // 123/udp: mode 3(클라이언트) 요청 → mode 4(서버) 응답이면 NTP 서버. stratum/refid를 설명으로 붙인다.
    public sealed class NtpProbe : IFactProbe
    {
        public const int DefaultPort = 123;
        private readonly int _port;
        public NtpProbe() : this(DefaultPort) { }
        internal NtpProbe(int port) => _port = port;
        public string Name => "NTP";

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (!UdpServiceProbes.ShouldRun(openPorts, DefaultPort) || !IPAddress.TryParse(ip, out IPAddress? addr)) return UdpServiceProbes.Empty;
                byte[]? reply = await UdpExchange.SendReceiveAsync(addr, _port, BuildRequest(), timeoutMs, 1, IsServerReply, ct).ConfigureAwait(false);
                return reply == null ? UdpServiceProbes.Empty : FactsFromReply(ip, reply);
            }
            catch
            {
                return UdpServiceProbes.Empty;
            }
        }

        public static byte[] BuildRequest()
        {
            var b = new byte[48];
            b[0] = 0x23;   // LI=0, VN=4, Mode=3
            // 전송 타임스탬프(초) — 1900년 기준
            uint secs = (uint)(DateTime.UtcNow - new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            b[40] = (byte)(secs >> 24); b[41] = (byte)(secs >> 16); b[42] = (byte)(secs >> 8); b[43] = (byte)secs;
            return b;
        }

        internal static bool IsServerReply(byte[] d) => d.Length >= 48 && (d[0] & 0x07) is 4 or 5 /* server / broadcast */;

        internal static IReadOnlyList<Fact> FactsFromReply(string ip, byte[] d)
        {
            if (!IsServerReply(d)) return UdpServiceProbes.Empty;
            var hf = new HostFacts(ip);
            int version = (d[0] >> 3) & 0x07;
            int stratum = d[1];
            string refId;
            if (stratum <= 1)
            {
                // stratum 0/1의 refid는 ASCII 식별자(GPS, LOCL, PPS …)
                refId = Encoding.ASCII.GetString(d, 12, 4).Trim('\0', ' ');
                if (refId.Any(c => c < 0x20 || c > 0x7E)) refId = "";
            }
            else
            {
                refId = string.Create(CultureInfo.InvariantCulture, $"{d[12]}.{d[13]}.{d[14]}.{d[15]}");
            }
            hf.Add(FactFields.Service, $"NTP server (v{version}, stratum {stratum})", UdpServiceProbes.Source, Confidence.Medium);
            string desc = stratum == 0 ? "NTP: unsynchronized (kiss-o'-death)" : $"NTP: stratum {stratum}" + (refId.Length > 0 ? $", ref {refId}" : "");
            hf.Add(FactFields.Description, desc, UdpServiceProbes.Source, Confidence.Low);
            return hf.All;
        }
    }

    // 1900/udp 유니캐스트 M-SEARCH. 응답 헤더와 LOCATION 설명 XML을 SsdpDiscovery와 같은 방식으로 해석한다.
    public sealed class SsdpUnicastProbe : IFactProbe
    {
        public const int DefaultPort = 1900;
        private readonly int _port;
        private readonly bool _fetchDescription;
        public SsdpUnicastProbe() : this(DefaultPort, fetchDescription: true) { }
        internal SsdpUnicastProbe(int port, bool fetchDescription) { _port = port; _fetchDescription = fetchDescription; }
        public string Name => "SSDP";

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (!UdpServiceProbes.ShouldRun(openPorts, DefaultPort) || !IPAddress.TryParse(ip, out IPAddress? addr)) return UdpServiceProbes.Empty;
                var hosts = new Dictionary<string, SsdpHost>(StringComparer.Ordinal);
                byte[]? reply = await UdpExchange.SendReceiveAsync(addr, _port, SsdpDiscovery.BuildMSearch(1), timeoutMs, 1, d =>
                {
                    SsdpDiscovery.SsdpResponse? r = SsdpDiscovery.ParseResponse(d);
                    return r != null && r.IsOk;
                }, ct).ConfigureAwait(false);
                if (reply == null) return UdpServiceProbes.Empty;
                SsdpDiscovery.Accumulate(hosts, addr, reply);
                if (_fetchDescription && !ct.IsCancellationRequested) await SsdpDiscovery.FetchDescriptionsAsync(hosts, ct).ConfigureAwait(false);
                return hosts.TryGetValue(ip, out SsdpHost? h) ? Retag(SsdpDiscovery.FactsFromHost(h)) : UdpServiceProbes.Empty;
            }
            catch
            {
                return UdpServiceProbes.Empty;
            }
        }

        // 프로브 출처는 "UDP"로 통일한다. 서비스가 하나도 없으면 최소한 "SSDP/UPnP"는 남긴다.
        private static IReadOnlyList<Fact> Retag(IReadOnlyList<Fact> facts)
        {
            var list = facts.Select(f => f with { Source = UdpServiceProbes.Source }).ToList();
            if (!list.Any(f => f.Field == FactFields.Service))
                list.Add(new Fact(FactFields.Service, "SSDP/UPnP", UdpServiceProbes.Source, Confidence.Medium));
            return list;
        }
    }

    // 69/udp: 임의 파일명으로 RRQ를 보낸다. DATA든 ERROR든 답이 오면 TFTP 서버(인증 없는 읽기 노출을 설명에 적는다).
    public sealed class TftpProbe : IFactProbe
    {
        public const int DefaultPort = 69;
        private readonly int _port;
        public TftpProbe() : this(DefaultPort) { }
        internal TftpProbe(int port) => _port = port;
        public string Name => "TFTP";

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (!UdpServiceProbes.ShouldRun(openPorts, DefaultPort) || !IPAddress.TryParse(ip, out IPAddress? addr)) return UdpServiceProbes.Empty;
                string file = "ns-" + Guid.NewGuid().ToString("N").Substring(0, 10) + ".bin";
                // TFTP 서버는 다른(임시) 포트에서 답하므로 주소만 맞으면 받는다(UdpExchange는 주소만 비교).
                byte[]? reply = await UdpExchange.SendReceiveAsync(addr, _port, BuildReadRequest(file), timeoutMs, 1, IsTftpReply, ct).ConfigureAwait(false);
                return reply == null ? UdpServiceProbes.Empty : FactsFromReply(ip, reply);
            }
            catch
            {
                return UdpServiceProbes.Empty;
            }
        }

        public static byte[] BuildReadRequest(string file)
        {
            var b = new List<byte> { 0, 1 };   // RRQ
            b.AddRange(Encoding.ASCII.GetBytes(file)); b.Add(0);
            b.AddRange(Encoding.ASCII.GetBytes("octet")); b.Add(0);
            return b.ToArray();
        }

        internal static bool IsTftpReply(byte[] d) => d.Length >= 4 && d[0] == 0 && (d[1] == 3 /* DATA */ || d[1] == 5 /* ERROR */ || d[1] == 6 /* OACK */);

        internal static IReadOnlyList<Fact> FactsFromReply(string ip, byte[] d)
        {
            if (!IsTftpReply(d)) return UdpServiceProbes.Empty;
            var hf = new HostFacts(ip);
            hf.Add(FactFields.Service, "TFTP server", UdpServiceProbes.Source, Confidence.Low);
            string detail = d[1] == 5 && d.Length > 4
                ? "error " + ((d[2] << 8) | d[3]).ToString(CultureInfo.InvariantCulture) + " " + Encoding.ASCII.GetString(d, 4, Math.Max(0, Array.IndexOf(d, (byte)0, 4) - 4)).Trim()
                : d[1] == 3 ? "served data for a random filename" : "option ack";
            hf.Add(FactFields.Description, "TFTP: answers unauthenticated read requests (" + detail + ") — exposure", UdpServiceProbes.Source, Confidence.Low);
            return hf.All;
        }
    }

    // 5060/udp: SIP OPTIONS → 상태줄로 시작하는 응답이 오면 User-Agent/Server를 서비스로, 종류는 voip.
    public sealed class SipProbe : IFactProbe
    {
        public const int DefaultPort = 5060;
        private readonly int _port;
        public SipProbe() : this(DefaultPort) { }
        internal SipProbe(int port) => _port = port;
        public string Name => "SIP";

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            try
            {
                if (!UdpServiceProbes.ShouldRun(openPorts, DefaultPort) || !IPAddress.TryParse(ip, out IPAddress? addr)) return UdpServiceProbes.Empty;
                string local = LocalAddressFor(addr) ?? "0.0.0.0";
                byte[]? reply = await UdpExchange.SendReceiveAsync(addr, _port, BuildOptions(ip, local), timeoutMs, 1,
                    d => d.Length > 8 && Encoding.ASCII.GetString(d, 0, 8).StartsWith("SIP/2.0 ", StringComparison.Ordinal), ct).ConfigureAwait(false);
                return reply == null ? UdpServiceProbes.Empty : FactsFromReply(ip, Encoding.UTF8.GetString(reply));
            }
            catch
            {
                return UdpServiceProbes.Empty;
            }
        }

        public static byte[] BuildOptions(string targetIp, string localIp)
        {
            string tag = Guid.NewGuid().ToString("N").Substring(0, 8);
            string text = $"OPTIONS sip:{targetIp} SIP/2.0\r\n" +
                          $"Via: SIP/2.0/UDP {localIp};branch=z9hG4bK{tag};rport\r\n" +
                          "Max-Forwards: 70\r\n" +
                          $"From: <sip:netscan@{localIp}>;tag={tag}\r\n" +
                          $"To: <sip:{targetIp}>\r\n" +
                          $"Call-ID: {Guid.NewGuid():N}@{localIp}\r\n" +
                          "CSeq: 1 OPTIONS\r\n" +
                          $"Contact: <sip:netscan@{localIp}>\r\n" +
                          "Accept: application/sdp\r\n" +
                          "User-Agent: NetworkScanner/2.1\r\n" +
                          "Content-Length: 0\r\n\r\n";
            return Encoding.ASCII.GetBytes(text);
        }

        internal static IReadOnlyList<Fact> FactsFromReply(string ip, string text)
        {
            SsdpDiscovery.SsdpResponse? r = SsdpDiscovery.ParseResponse(text);   // "상태줄 + 헤더" 형식이 같다
            if (r == null || !r.StatusLine.StartsWith("SIP/2.0 ", StringComparison.Ordinal)) return UdpServiceProbes.Empty;
            var hf = new HostFacts(ip);
            string? agent = r.Get("User-Agent") ?? r.Get("Server");
            hf.Add(FactFields.Service, agent != null ? "SIP: " + agent : "SIP (" + r.StatusLine.Substring(8).Trim() + ")", UdpServiceProbes.Source, Confidence.Medium);
            hf.Add(FactFields.DeviceType, "voip", UdpServiceProbes.Source, Confidence.Medium);
            return hf.All;
        }

        // 대상으로 가는 경로의 로컬 주소(Via/From에 넣는다). 실패하면 null.
        private static string? LocalAddressFor(IPAddress target)
        {
            try
            {
                using var s = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                s.Connect(new IPEndPoint(target, DefaultPort));
                return (s.LocalEndPoint as IPEndPoint)?.Address.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}
