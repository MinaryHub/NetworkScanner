using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Infrastructure
{
    // Linux 전용 능동 ARP 프로브(최선 노력). AF_PACKET 원시 소켓으로 인터페이스에 직접 who-has를 쏘고 응답을 듣는다.
    // 핑/방화벽에 막힌 호스트도 ARP에는 답하므로 서브넷 내 생존 확인에 가장 확실하다. CAP_NET_RAW(또는 root)가 필요하다.
    // macOS/Windows이거나 소켓을 만들 수 없으면 IsSupported=false 이고 빈 결과를 돌려준다(예외 없음).
    public static class ActiveArpProber
    {
        private const int EthPArp = 0x0806;
        private const int ProtocolHtonsArp = 0x0608; // htons(ETH_P_ARP): 리틀엔디언 호스트의 socket() 인자
        private const int FrameSize = 42;             // Ethernet 14 + ARP 28
        private const int MaxReceiveFrame = 1600;

        private static readonly Lazy<bool> _supported = new(DetectSupport, LazyThreadSafetyMode.ExecutionAndPublication);

        public static bool IsSupported => _supported.Value;

        private static bool DetectSupport()
        {
            if (!OperatingSystem.IsLinux()) return false;
            try
            {
                using var s = CreatePacketSocket();
                return true;
            }
            catch (SocketException) { return false; }   // EPERM: CAP_NET_RAW 없음
            catch (Exception) { return false; }
        }

        [SupportedOSPlatform("linux")]
        private static Socket CreatePacketSocket() => new(AddressFamily.Packet, SocketType.Raw, (ProtocolType)ProtocolHtonsArp);

        // targets의 각 IPv4에 who-has를 보내고 timeoutMs 동안 응답을 모아 ip → MAC("AA-BB-…") 사전을 돌려준다.
        // 어떤 로컬 서브넷에도 속하지 않는 대상은 건너뛴다(ARP는 링크 안에서만 통한다).
        public static async Task<IReadOnlyDictionary<string, string>> ProbeAsync(IEnumerable<IPAddress> targets, int timeoutMs, CancellationToken ct)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!IsSupported || timeoutMs <= 0 || !OperatingSystem.IsLinux()) return result;

            try
            {
                List<IPAddress> v4 = targets.Where(t => t.AddressFamily == AddressFamily.InterNetwork).Distinct().ToList();
                if (v4.Count == 0) return result;

                foreach ((LinkInfo link, List<IPAddress> group) in GroupByInterface(v4))
                {
                    ct.ThrowIfCancellationRequested();
                    await ProbeOnInterfaceAsync(link, group, timeoutMs, result, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                AppLogger.LogDebug(nameof(ActiveArpProber), "ARP 프로브 실패: " + ex.Message);
            }
            return result;
        }

        internal sealed class LinkInfo
        {
            public string Name = "";
            public int Index;
            public byte[] Mac = Array.Empty<byte>();
            public byte[] Ip = Array.Empty<byte>();
            public uint Network;
            public uint Mask;
        }

        // 동작 중인 이더넷/무선 인터페이스(IPv4 + 6바이트 MAC) 목록.
        internal static List<LinkInfo> EnumerateLinks()
        {
            var links = new List<LinkInfo>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                    byte[] mac;
                    try { mac = nic.GetPhysicalAddress().GetAddressBytes(); } catch { continue; }
                    if (mac.Length != 6) continue;
                    IPInterfaceProperties props;
                    int index;
                    try { props = nic.GetIPProperties(); index = props.GetIPv4Properties().Index; } catch { continue; }
                    foreach (UnicastIPAddressInformation u in props.UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != AddressFamily.InterNetwork || u.IPv4Mask == null) continue;
                        uint ip = BinaryPrimitives.ReadUInt32BigEndian(u.Address.GetAddressBytes());
                        uint mask = BinaryPrimitives.ReadUInt32BigEndian(u.IPv4Mask.GetAddressBytes());
                        if (mask == 0) continue;
                        links.Add(new LinkInfo { Name = nic.Name, Index = index, Mac = mac, Ip = u.Address.GetAddressBytes(), Network = ip & mask, Mask = mask });
                    }
                }
            }
            catch { }
            return links;
        }

        private static IEnumerable<(LinkInfo Link, List<IPAddress> Targets)> GroupByInterface(List<IPAddress> targets)
        {
            List<LinkInfo> links = EnumerateLinks();
            var groups = new Dictionary<LinkInfo, List<IPAddress>>();
            foreach (IPAddress t in targets)
            {
                uint ip = BinaryPrimitives.ReadUInt32BigEndian(t.GetAddressBytes());
                LinkInfo? link = links.FirstOrDefault(l => (ip & l.Mask) == l.Network);
                if (link == null) continue;
                if (!groups.TryGetValue(link, out List<IPAddress>? list)) { list = new List<IPAddress>(); groups[link] = list; }
                list.Add(t);
            }
            return groups.Select(kv => (kv.Key, kv.Value));
        }

        [SupportedOSPlatform("linux")]
        private static async Task ProbeOnInterfaceAsync(LinkInfo link, List<IPAddress> targets, int timeoutMs, Dictionary<string, string> result, CancellationToken ct)
        {
            var wanted = new HashSet<string>(targets.Select(t => t.ToString()), StringComparer.Ordinal);
            using var socket = CreatePacketSocket();
            var endpoint = new PacketEndPoint(link.Index, BroadcastMac);
            socket.Bind(endpoint);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);

            // 수신 루프를 먼저 띄우고 나서 요청을 보낸다(빠른 응답을 놓치지 않도록).
            Task receiver = Task.Run(async () =>
            {
                var buffer = new byte[MaxReceiveFrame];
                try
                {
                    while (!cts.IsCancellationRequested)
                    {
                        int n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
                        if (n < FrameSize) continue;
                        if (TryParseArp(buffer.AsSpan(0, n), out string senderIp, out string senderMac) && wanted.Contains(senderIp))
                        {
                            lock (result) result[senderIp] = senderMac;
                        }
                    }
                }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
                catch (SocketException) { }
            }, cts.Token);

            try
            {
                int sent = 0;
                foreach (IPAddress t in targets)
                {
                    if (cts.IsCancellationRequested) break;
                    byte[] frame = BuildWhoHas(link.Mac, link.Ip, t.GetAddressBytes());
                    try { socket.SendTo(frame, endpoint); } catch (SocketException) { }
                    if (++sent % 32 == 0) await Task.Delay(2, cts.Token).ConfigureAwait(false); // 스위치/대상 버퍼를 배려한 소량 지연
                }
                // 남은 시간 동안 응답을 기다린다.
                await Task.Delay(Timeout.Infinite, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            finally
            {
                cts.Cancel();
                try { socket.Close(); } catch { }
                try { await receiver.ConfigureAwait(false); } catch { }
            }
        }

        private static readonly byte[] BroadcastMac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        // Ethernet(14) + ARP(28) who-has 프레임.
        internal static byte[] BuildWhoHas(ReadOnlySpan<byte> srcMac, ReadOnlySpan<byte> srcIp, ReadOnlySpan<byte> targetIp)
        {
            var f = new byte[FrameSize];
            BroadcastMac.CopyTo(f, 0);                  // dst
            srcMac.CopyTo(f.AsSpan(6, 6));              // src
            f[12] = EthPArp >> 8; f[13] = EthPArp & 0xFF;
            f[14] = 0x00; f[15] = 0x01;                 // htype Ethernet
            f[16] = 0x08; f[17] = 0x00;                 // ptype IPv4
            f[18] = 6; f[19] = 4;                       // hlen, plen
            f[20] = 0x00; f[21] = 0x01;                 // opcode request
            srcMac.CopyTo(f.AsSpan(22, 6));             // sender MAC
            srcIp.CopyTo(f.AsSpan(28, 4));              // sender IP
            // target MAC 00…(32..37)
            targetIp.CopyTo(f.AsSpan(38, 4));           // target IP
            return f;
        }

        // 수신 프레임이 IPv4 ARP(요청/응답 모두)이면 보낸 쪽 IP/MAC을 돌려준다. 요청을 보내는 호스트도 살아 있는 증거다.
        internal static bool TryParseArp(ReadOnlySpan<byte> frame, out string senderIp, out string senderMac)
        {
            senderIp = ""; senderMac = "";
            if (frame.Length < FrameSize) return false;
            if (frame[12] != (EthPArp >> 8) || frame[13] != (EthPArp & 0xFF)) return false;
            if (frame[14] != 0 || frame[15] != 1 || frame[16] != 0x08 || frame[17] != 0x00 || frame[18] != 6 || frame[19] != 4) return false;
            int op = (frame[20] << 8) | frame[21];
            if (op != 1 && op != 2) return false;
            string? mac = InfrastructureFacts.MacFromBytes(frame.Slice(22, 6));
            if (!InfrastructureFacts.IsUsableMac(mac)) return false;
            senderMac = mac!;
            senderIp = $"{frame[28]}.{frame[29]}.{frame[30]}.{frame[31]}";
            return senderIp != "0.0.0.0";
        }

        // sockaddr_ll(20바이트)의 family 뒤 18바이트: protocol(네트워크 순서) @0, ifindex(호스트 순서) @2, hatype @6, pkttype @8, halen @9, addr @10.
        internal static byte[] BuildSockaddrLlBody(int ifIndex, ReadOnlySpan<byte> hwAddr)
        {
            var b = new byte[18];
            b[0] = EthPArp >> 8; b[1] = EthPArp & 0xFF;
            BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(2, 4), ifIndex);
            b[9] = (byte)Math.Min(hwAddr.Length, 8);
            hwAddr.Slice(0, Math.Min(hwAddr.Length, 8)).CopyTo(b.AsSpan(10));
            return b;
        }

        // struct sockaddr_ll을 .NET EndPoint로. family는 SocketAddress가 플랫폼 값(AF_PACKET=17)으로 채운다.
        internal sealed class PacketEndPoint : EndPoint
        {
            public int InterfaceIndex { get; }
            public byte[] HardwareAddress { get; }

            public PacketEndPoint(int interfaceIndex, byte[] hardwareAddress)
            {
                InterfaceIndex = interfaceIndex;
                HardwareAddress = hardwareAddress;
            }

            public override AddressFamily AddressFamily => AddressFamily.Packet;

            public override SocketAddress Serialize()
            {
                var sa = new SocketAddress(AddressFamily.Packet, 20);
                byte[] body = BuildSockaddrLlBody(InterfaceIndex, HardwareAddress);
                for (int i = 0; i < body.Length; i++) sa[2 + i] = body[i];
                return sa;
            }

            public override EndPoint Create(SocketAddress socketAddress)
            {
                if (socketAddress.Size < 20) return new PacketEndPoint(0, Array.Empty<byte>());
                int ifIndex = socketAddress[4] | (socketAddress[5] << 8) | (socketAddress[6] << 16) | (socketAddress[7] << 24);
                int halen = Math.Min((int)socketAddress[11], 8);
                var hw = new byte[halen];
                for (int i = 0; i < halen; i++) hw[i] = socketAddress[12 + i];
                return new PacketEndPoint(ifIndex, hw);
            }

            public override string ToString() => $"packet:if{InterfaceIndex}";
        }
    }

    // 능동 ARP 프로브를 INetworkDiscovery로 감싼다. 대상 목록은 생성자로 받는다(보통 스캔 대역의 IPv4 전체).
    public sealed class ActiveArpDiscovery : INetworkDiscovery
    {
        private readonly IPAddress[] _targets;

        public ActiveArpDiscovery(IEnumerable<IPAddress> targets)
        {
            _targets = targets.Where(t => t != null).ToArray();
        }

        public string Name => InfrastructureFacts.SourceArpProbe;

        public static bool IsSupported => ActiveArpProber.IsSupported;

        public async Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
        {
            var result = new Dictionary<string, IReadOnlyList<Fact>>(StringComparer.Ordinal);
            if (!ActiveArpProber.IsSupported || _targets.Length == 0) return result;

            IReadOnlyDictionary<string, string> replies = await ActiveArpProber.ProbeAsync(_targets, timeoutMs, ct).ConfigureAwait(false);
            const string source = InfrastructureFacts.SourceArpProbe;
            foreach (var (ip, mac) in replies)
            {
                result[ip] = new[]
                {
                    new Fact(FactFields.Mac, mac, source, Confidence.High),
                    new Fact(InfrastructureFacts.SeenByField, InfrastructureFacts.SeenByArpProbe, source, Confidence.Medium),
                };
            }
            return result;
        }
    }
}
