using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using KetworkScanner.Discovery;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace KetworkScanner.Capture
{
    // 수동 패킷 리스너. libpcap/Npcap(SharpPcap)으로 ARP·DHCP·mDNS·SSDP·NetBIOS·TCP SYN-ACK만 걸러 받아
    // 패킷마다 HostObservation을 만들어 Observed로 흘려보낸다. 캡처는 SharpPcap의 백그라운드 스레드에서 돌고
    // Observed도 그 스레드에서 호출되므로 구독자는 스레드 안전해야 한다(ObservationAggregator는 안전).
    // 라이브러리·권한·인터페이스가 없으면 예외 대신 IsAvailable=false + UnavailableReason으로 조용히 물러난다.
    public sealed class PassiveListener : IDisposable
    {
        public const string Filter =
            "arp or (udp and (port 67 or port 68 or port 5353 or port 1900 or port 137)) or (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))";

        public const string SourceArp = "pcap-arp", SourceDhcp = "pcap-dhcp", SourceMdns = "pcap-mdns",
            SourceSsdp = "pcap-ssdp", SourceNetBios = "pcap-netbios", SourceTcp = "pcap-tcp";

        // FactFields에 없는 부가 필드: 원본 핑거프린트 문자열(UI 상세 표시용).
        public const string FieldDhcpFingerprint = "dhcpFingerprint";
        public const string FieldTcpSignature = "tcpSignature";

        private const uint PcapIfLoopback = 0x1, PcapIfUp = 0x2, PcapIfRunning = 0x4;
        private const string LogSource = "PassiveListener";

        private readonly object _lock = new();
        private readonly string? _interfaceName;
        private LibPcapLiveDevice? _device;
        private (uint Network, uint Mask)? _onLink;
        private long _packets, _observations, _decodeErrors;

        public event Action<HostObservation>? Observed;

        public bool IsAvailable { get; private set; }
        public bool IsRunning { get; private set; }
        public string UnavailableReason { get; private set; } = "";
        public string InterfaceName { get; private set; } = "";
        public long PacketsSeen => Interlocked.Read(ref _packets);
        public long ObservationsRaised => Interlocked.Read(ref _observations);

        // interfaceName: pcap 장치 이름(en0, \Device\NPF_{…}) 또는 FriendlyName/설명. null이면 첫 번째 활성 IPv4 인터페이스.
        public PassiveListener(string? interfaceName = null)
        {
            _interfaceName = string.IsNullOrWhiteSpace(interfaceName) ? null : interfaceName.Trim();
        }

        // 캡처가 가능한지 미리 본다: 장치 열거 → 첫 활성 non-loopback IPv4 인터페이스를 비혼잡 모드·1초 타임아웃으로 열고 바로 닫는다.
        public static (bool Available, string Reason) Probe() => Probe(null);

        public static (bool Available, string Reason) Probe(string? interfaceName)
        {
            try
            {
                IReadOnlyList<LibPcapLiveDevice> devices = ListDevices();
                if (devices.Count == 0) return (false, "캡처 가능한 인터페이스가 없습니다 (libpcap 권한 부족 또는 드라이버 미설치)");
                LibPcapLiveDevice? dev = SelectDevice(devices, interfaceName);
                if (dev == null) return (false, interfaceName == null ? "활성 IPv4 인터페이스를 찾지 못했습니다" : $"인터페이스를 찾지 못했습니다: {interfaceName}");
                dev.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 1000 });
                try { return (true, $"OK: {Describe(dev)} ({dev.LinkType})"); }
                finally { try { dev.Close(); } catch { } }
            }
            catch (Exception ex)
            {
                return (false, ExplainFailure(ex));
            }
        }

        // 캡처를 시작한다. 실패해도 던지지 않고 false + UnavailableReason.
        public bool Start()
        {
            lock (_lock)
            {
                if (_device != null) return true;
                LibPcapLiveDevice? dev = null;
                try
                {
                    IReadOnlyList<LibPcapLiveDevice> devices = ListDevices();
                    dev = SelectDevice(devices, _interfaceName);
                    if (dev == null)
                        throw new InvalidOperationException(_interfaceName == null ? "활성 IPv4 인터페이스를 찾지 못했습니다" : $"인터페이스를 찾지 못했습니다: {_interfaceName}");

                    dev.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 1000, Immediate = true });
                    dev.Filter = Filter;
                    _onLink = OnLinkSubnet(dev);
                    dev.OnPacketArrival += OnPacketArrival;
                    dev.OnCaptureStopped += OnCaptureStopped;
                    dev.StartCapture();

                    _device = dev;
                    IsAvailable = true;
                    IsRunning = true;
                    UnavailableReason = "";
                    InterfaceName = dev.Name;
                    AppLogger.LogInfo(LogSource, $"수동 캡처 시작: {Describe(dev)} ({dev.LinkType})");
                    return true;
                }
                catch (Exception ex)
                {
                    IsAvailable = false;
                    IsRunning = false;
                    UnavailableReason = ExplainFailure(ex);
                    AppLogger.LogWarn(LogSource, "수동 캡처를 시작하지 못했습니다: " + UnavailableReason);
                    if (dev != null)
                    {
                        try { dev.OnPacketArrival -= OnPacketArrival; dev.OnCaptureStopped -= OnCaptureStopped; } catch { }
                        try { dev.Close(); } catch { }
                        try { dev.Dispose(); } catch { }
                    }
                    return false;
                }
            }
        }

        public void Stop()
        {
            LibPcapLiveDevice? dev;
            lock (_lock)
            {
                dev = _device;
                _device = null;
                IsRunning = false;
            }
            if (dev == null) return;
            try { dev.OnPacketArrival -= OnPacketArrival; dev.OnCaptureStopped -= OnCaptureStopped; } catch { }
            try { if (dev.Started) dev.StopCapture(); } catch (Exception ex) { AppLogger.LogDebug(LogSource, "StopCapture: " + ex.Message); }
            try { dev.Close(); } catch { }
            try { dev.Dispose(); } catch { }
            AppLogger.LogInfo(LogSource, $"수동 캡처 중지 (패킷 {PacketsSeen}, 관찰 {ObservationsRaised})");
        }

        public void Dispose() => Stop();

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            RawCapture raw;
            try { raw = e.GetPacket(); }
            catch { Interlocked.Increment(ref _decodeErrors); return; }
            Interlocked.Increment(ref _packets);

            HostObservation? obs;
            try { obs = Decode(raw.Data, raw.LinkLayerType, DateTimeOffset.UtcNow, _onLink); }
            catch (Exception ex)
            {
                if (Interlocked.Increment(ref _decodeErrors) <= 3) AppLogger.LogDebug(LogSource, "패킷 디코드 실패: " + ex.Message);
                return;
            }
            if (obs == null) return;
            Interlocked.Increment(ref _observations);
            try { Observed?.Invoke(obs); }
            catch (Exception ex) { AppLogger.LogWarn(LogSource, "Observed 핸들러 예외: " + ex.Message); }
        }

        private void OnCaptureStopped(object sender, CaptureStoppedEventStatus status)
        {
            if (status == CaptureStoppedEventStatus.CompletedWithoutError) return;
            lock (_lock)
            {
                if (_device == null) return; // 우리가 Stop()한 경우
                IsRunning = false;
                UnavailableReason = $"캡처가 중단되었습니다: {status}";
            }
            AppLogger.LogWarn(LogSource, UnavailableReason);
        }

        // ---------- 장치 선택 ----------

        private static IReadOnlyList<LibPcapLiveDevice> ListDevices()
        {
            // Instance는 프로세스 수명 동안 캐시되므로 매번 새로 읽는다(인터페이스 변경 반영).
            return CaptureDeviceList.New().OfType<LibPcapLiveDevice>().ToList();
        }

        private static LibPcapLiveDevice? SelectDevice(IReadOnlyList<LibPcapLiveDevice> devices, string? name)
        {
            if (name != null)
            {
                return devices.FirstOrDefault(d =>
                    string.Equals(d.Name, name, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.Interface?.FriendlyName, name, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(d.Description, name, StringComparison.OrdinalIgnoreCase));
            }

            List<NicInfo> nics = DotNetNics();
            var candidates = devices.Where(d => !d.Loopback && (d.Flags & PcapIfLoopback) == 0 && d.Name != "any" && Ipv4Of(d, nics) != null).ToList();
            // .NET이 먼저 꼽는 활성 IPv4 NIC(LocalNetworkInfo와 같은 기준) → UP+RUNNING → UP 순.
            NicInfo? preferred = nics.FirstOrDefault();
            return candidates.FirstOrDefault(d => preferred != null && preferred.Ip.Equals(Ipv4Of(d, nics)?.Ip))
                ?? candidates.FirstOrDefault(d => (d.Flags & PcapIfUp) != 0 && (d.Flags & PcapIfRunning) != 0)
                ?? candidates.FirstOrDefault(d => (d.Flags & PcapIfUp) != 0)
                ?? candidates.FirstOrDefault();
        }

        private sealed record NicInfo(string Name, string Id, IPAddress Ip, IPAddress Mask);

        // .NET이 보는 활성 IPv4 인터페이스. SharpPcap이 주소를 못 읽는 플랫폼(macOS 일부 버전)에서 대체 정보로 쓴다.
        private static List<NicInfo> DotNetNics()
        {
            var list = new List<NicInfo>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces()
                             .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel))
                {
                    foreach (UnicastIPAddressInformation a in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (a.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(a.Address) || a.IPv4Mask == null) continue;
                        list.Add(new NicInfo(nic.Name, nic.Id, a.Address, a.IPv4Mask));
                        break;
                    }
                }
            }
            catch { }
            return list;
        }

        // pcap 장치 ↔ .NET NIC 대응. Unix는 이름이 같고(en0), Windows는 \Device\NPF_{GUID}에 NIC Id({GUID})가 들어 있다.
        private static NicInfo? NicFor(LibPcapLiveDevice d, List<NicInfo> nics) =>
            nics.FirstOrDefault(n => string.Equals(n.Name, d.Name, StringComparison.OrdinalIgnoreCase))
            ?? nics.FirstOrDefault(n => n.Id.Length > 0 && d.Name.Contains(n.Id, StringComparison.OrdinalIgnoreCase));

        private static (IPAddress Ip, IPAddress? Mask)? Ipv4Of(LibPcapLiveDevice d, List<NicInfo> nics)
        {
            try
            {
                PcapAddress? a = d.Addresses.FirstOrDefault(x => x.Addr?.ipAddress?.AddressFamily == AddressFamily.InterNetwork);
                if (a?.Addr?.ipAddress != null) return (a.Addr.ipAddress, a.Netmask?.ipAddress);
            }
            catch { }
            NicInfo? nic = NicFor(d, nics);
            return nic == null ? null : (nic.Ip, nic.Mask);
        }

        private static (uint, uint)? OnLinkSubnet(LibPcapLiveDevice d)
        {
            var a = Ipv4Of(d, DotNetNics());
            if (a?.Mask == null) return null;
            uint ip = IPRangeUtil.ToUInt32(a.Value.Ip);
            uint mask = IPRangeUtil.ToUInt32(a.Value.Mask);
            if (mask == 0) return null;
            return (ip & mask, mask);
        }

        private static string Describe(LibPcapLiveDevice d)
        {
            string friendly = d.Interface?.FriendlyName ?? d.Description ?? "";
            string ip = Ipv4Of(d, DotNetNics())?.Ip.ToString() ?? "";
            return string.IsNullOrEmpty(friendly) || friendly == d.Name ? $"{d.Name} {ip}".Trim() : $"{d.Name} ({friendly}) {ip}".Trim();
        }

        // 예외 → 사용자에게 보여줄 한 줄 이유. 네이티브 라이브러리 부재와 권한 부족을 구분한다.
        internal static string ExplainFailure(Exception ex)
        {
            Exception root = ex;
            while (root is TypeInitializationException or System.Reflection.TargetInvocationException && root.InnerException != null) root = root.InnerException;

            if (root is DllNotFoundException || root is EntryPointNotFoundException || root is BadImageFormatException || root.Message.Contains("wpcap", StringComparison.OrdinalIgnoreCase) || root.Message.Contains("libpcap", StringComparison.OrdinalIgnoreCase))
            {
                string hint = OperatingSystem.IsWindows() ? "Npcap(https://npcap.com)을 설치하세요"
                            : OperatingSystem.IsLinux() ? "libpcap 패키지(libpcap0.8 / libpcap)를 설치하세요"
                            : "libpcap을 찾을 수 없습니다";
                return $"패킷 캡처 라이브러리 없음: {hint} ({root.GetType().Name})";
            }

            string m = root.Message;
            bool pcapPermission = root is PcapException pe && pe.Error is PcapError.PermissionDenied or PcapError.PromiscuousPermissionDenied;
            if (pcapPermission || m.Contains("ermission", StringComparison.Ordinal) || m.Contains("not permitted", StringComparison.OrdinalIgnoreCase) || m.Contains("BPF", StringComparison.Ordinal) || m.Contains("EPERM", StringComparison.Ordinal) || m.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
            {
                string hint = OperatingSystem.IsWindows() ? "Npcap 설치 시 'Restrict to Administrators'를 끄거나 관리자로 실행하세요"
                            : OperatingSystem.IsMacOS() ? "/dev/bpf* 접근 권한이 필요합니다 (Wireshark의 ChmodBPF 설치 또는 sudo)"
                            : "CAP_NET_RAW,CAP_NET_ADMIN 권한이 필요합니다 (setcap 또는 root)";
                return $"캡처 권한 없음: {hint} — {m}";
            }
            return $"{root.GetType().Name}: {m}";
        }

        // ---------- 디코딩 (정적, 테스트 가능) ----------

        internal static HostObservation? Decode(byte[] raw, LinkLayers linkType = LinkLayers.Ethernet) => Decode(raw, linkType, DateTimeOffset.UtcNow, null);

        // onLink: 캡처 인터페이스의 (네트워크, 마스크). 라우팅된 TCP 패킷의 이더넷 MAC(=게이트웨이)을 호스트 MAC으로 오인하지 않기 위해 쓴다. null이면 검사 안 함.
        internal static HostObservation? Decode(byte[] raw, LinkLayers linkType, DateTimeOffset at, (uint Network, uint Mask)? onLink)
        {
            // PacketDotNet은 잘린/이상한 프레임에서 파싱뿐 아니라 Extract 중에도 던질 수 있다. 어떤 경우든 null.
            try { return DecodeCore(raw, linkType, at, onLink); }
            catch { return null; }
        }

        private static HostObservation? DecodeCore(byte[] raw, LinkLayers linkType, DateTimeOffset at, (uint Network, uint Mask)? onLink)
        {
            if (raw == null || raw.Length < 14) return null;
            Packet packet = Packet.ParsePacket(linkType, raw);

            ArpPacket? arp = packet.Extract<ArpPacket>();
            if (arp != null) return DecodeArp(arp, at);

            IPv4Packet? ip = packet.Extract<IPv4Packet>();
            if (ip == null) return null;
            string srcIp = ip.SourceAddress.ToString();
            if (srcIp == "0.0.0.0") srcIp = "";
            string ethMac = packet is EthernetPacket eth ? FormatMac(eth.SourceHardwareAddress) : "";

            UdpPacket? udp = packet.Extract<UdpPacket>();
            if (udp != null)
            {
                byte[] payload = UdpPayload(udp);
                if (Is(udp, 67) || Is(udp, 68)) return DecodeDhcp(payload, at);
                if (Is(udp, 5353)) return DecodeMdns(payload, srcIp, ethMac, at);
                if (Is(udp, 1900)) return DecodeSsdp(payload, srcIp, ethMac, at);
                if (Is(udp, 137)) return DecodeNetBios(payload, srcIp, ethMac, at);
                return null;
            }

            TcpPacket? tcp = packet.Extract<TcpPacket>();
            if (tcp != null && tcp.Synchronize && tcp.Acknowledgment && srcIp.Length > 0)
            {
                bool macTrusted = onLink == null || (IPRangeUtil.ToUInt32(ip.SourceAddress) & onLink.Value.Mask) == onLink.Value.Network;
                return DecodeTcpSynAck(ip, tcp, macTrusted ? ethMac : "", srcIp, at);
            }
            return null;
        }

        private static bool Is(UdpPacket udp, int port) => udp.SourcePort == port || udp.DestinationPort == port;

        private static byte[] UdpPayload(UdpPacket udp)
        {
            byte[] all = udp.Bytes;
            int header = 8;
            int len = Math.Min(all.Length, udp.Length) - header; // 이더넷 패딩은 UDP 길이로 잘라낸다
            if (len <= 0) return Array.Empty<byte>();
            return all.AsSpan(header, len).ToArray();
        }

        private static HostObservation? DecodeArp(ArpPacket arp, DateTimeOffset at)
        {
            if (arp.Operation != ArpOperation.Request && arp.Operation != ArpOperation.Response) return null;
            string mac = FormatMac(arp.SenderHardwareAddress);
            if (mac.Length == 0 || mac == "FF:FF:FF:FF:FF:FF") return null;
            string ip = arp.SenderProtocolAddress?.ToString() ?? "";
            if (ip == "0.0.0.0") ip = ""; // ARP probe(RFC 5227): 보낸 쪽 IP가 아직 없다
            var facts = new List<Fact> { new(FactFields.Mac, mac, SourceArp, Confidence.High) };
            return new HostObservation(ip, mac, SourceArp, facts, at);
        }

        internal static HostObservation? DecodeDhcp(byte[] payload, DateTimeOffset at)
        {
            if (!DhcpCodec.TryParse(payload, out DhcpMessage msg)) return null;
            if (msg.Mac.Length == 0) return null;
            var facts = new List<Fact>();
            string ip = msg.BestIp;

            if (msg.IsRequest)
            {
                if (!string.IsNullOrEmpty(msg.Hostname)) facts.Add(new Fact(FactFields.Name, msg.Hostname, SourceDhcp, Confidence.High));
                facts.AddRange(DhcpFingerprints.FactsFromVendorClass(msg.VendorClass, SourceDhcp));
                if (msg.ParameterRequestList.Length > 0)
                {
                    facts.Add(new Fact(FieldDhcpFingerprint, msg.Fingerprint, SourceDhcp, Confidence.Low));
                    DhcpFingerprints.Result? m = DhcpFingerprints.MatchFingerprint(msg.Fingerprint);
                    // 벤더 클래스가 이미 High로 OS를 말했으면 핑거프린트 결과는 보조로만 둔다.
                    if (m != null && !facts.Any(f => f.Field == FactFields.Os && f.Confidence == Confidence.High))
                        facts.Add(new Fact(FactFields.Os, m.Os, SourceDhcp, m.Confidence));
                }
                facts.Add(new Fact(FactFields.Description, "DHCP " + DhcpMessage.MessageTypeName(msg.MessageType), SourceDhcp, Confidence.Low));
            }
            else
            {
                // 서버 응답(OFFER/ACK): 클라이언트 MAC ↔ 배정 IP 결합이 핵심. 응답에 실린 호스트명(12)은 서버가 되돌려 준 값이다.
                if (msg.MessageType != 5 && msg.MessageType != 2) return null;
                if (!string.IsNullOrEmpty(msg.Hostname)) facts.Add(new Fact(FactFields.Name, msg.Hostname, SourceDhcp, Confidence.Medium));
            }
            facts.Add(new Fact(FactFields.Mac, msg.Mac, SourceDhcp, Confidence.High));
            return new HostObservation(ip, msg.Mac, SourceDhcp, facts, at);
        }

        // mDNS 서비스 타입 → 장비 종류 힌트.
        private static readonly (string Service, string DeviceType)[] MdnsServiceTypes =
        {
            ("_ipp._tcp", "printer"), ("_ipps._tcp", "printer"), ("_printer._tcp", "printer"), ("_pdl-datastream._tcp", "printer"), ("_scanner._tcp", "printer"),
            ("_airplay._tcp", "media"), ("_raop._tcp", "media"), ("_googlecast._tcp", "media"), ("_spotify-connect._tcp", "media"), ("_sonos._tcp", "media"),
            ("_hap._tcp", "iot"), ("_homekit._tcp", "iot"), ("_matter._tcp", "iot"), ("_hue._tcp", "iot"),
            ("_smb._tcp", "nas"), ("_afpovertcp._tcp", "nas"), ("_nfs._tcp", "nas"),
            ("_rdlink._tcp", "phone"), ("_companion-link._tcp", "apple"), ("_apple-mobdev2._tcp", "phone"),
            ("_ssh._tcp", "computer"), ("_rfb._tcp", "computer"), ("_workstation._tcp", "computer"),
            ("_http._tcp", "web"), ("_dosvc._tcp", "windows"),
        };

        internal static HostObservation? DecodeMdns(byte[] payload, string srcIp, string mac, DateTimeOffset at)
        {
            if (srcIp.Length == 0) return null;
            if (!DnsCodec.TryParseResponse(payload, out DnsCodec.Response resp) || !resp.IsResponse) return null;
            var facts = new List<Fact>();
            var records = resp.Answers.Concat(resp.Additional).ToList();

            // A 레코드: 보낸 IP와 같은 것을 우선, 없으면 첫 번째.
            DnsCodec.Record? a = records.FirstOrDefault(r => r.Type == DnsCodec.TypeA && r.Data == srcIp) ?? records.FirstOrDefault(r => r.Type == DnsCodec.TypeA);
            if (a != null && a.Name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Name, a.Name[..^".local".Length], SourceMdns, Confidence.Medium));

            foreach (DnsCodec.Record r in records)
            {
                if (r.Type == DnsCodec.TypeTxt)
                {
                    foreach (string kv in r.Data.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        int eq = kv.IndexOf('=');
                        if (eq <= 0) continue;
                        string k = kv[..eq].Trim(), v = kv[(eq + 1)..].Trim();
                        if (v.Length == 0) continue;
                        if (k.Equals("model", StringComparison.OrdinalIgnoreCase) || k.Equals("md", StringComparison.OrdinalIgnoreCase))
                            facts.Add(new Fact(FactFields.Model, v, SourceMdns, Confidence.Medium));
                        else if (k.Equals("osxvers", StringComparison.OrdinalIgnoreCase))
                            facts.Add(new Fact(FactFields.Os, "macOS", SourceMdns, Confidence.Medium));
                        else if (k.Equals("fn", StringComparison.OrdinalIgnoreCase))
                            facts.Add(new Fact(FactFields.Name, v, SourceMdns, Confidence.Low));
                        else if (k.Equals("ty", StringComparison.OrdinalIgnoreCase)) // 프린터 TXT: ty=HP LaserJet …
                            facts.Add(new Fact(FactFields.Model, v, SourceMdns, Confidence.Medium));
                    }
                }
                if (r.Type == DnsCodec.TypePtr || r.Type == DnsCodec.TypeSrv || r.Type == DnsCodec.TypeTxt)
                {
                    foreach (var (svc, type) in MdnsServiceTypes)
                    {
                        if (r.Name.Contains(svc + ".", StringComparison.OrdinalIgnoreCase) || r.Data.Contains(svc + ".", StringComparison.OrdinalIgnoreCase))
                        {
                            facts.Add(new Fact(FactFields.Service, svc, SourceMdns, Confidence.Low));
                            if (type == "apple") facts.Add(new Fact(FactFields.Vendor, "Apple", SourceMdns, Confidence.Low));
                            else if (type == "windows") facts.Add(new Fact(FactFields.Os, "Windows", SourceMdns, Confidence.Low));
                            else facts.Add(new Fact(FactFields.DeviceType, type, SourceMdns, Confidence.Low));
                        }
                    }
                }
            }
            if (facts.Count == 0) return null;
            return new HostObservation(srcIp, mac, SourceMdns, Dedupe(facts), at);
        }

        internal static HostObservation? DecodeSsdp(byte[] payload, string srcIp, string mac, DateTimeOffset at)
        {
            if (srcIp.Length == 0 || payload.Length < 16) return null;
            string text;
            try { text = Encoding.ASCII.GetString(payload); } catch { return null; }
            string[] lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string first = lines[0].Trim();
            // NOTIFY(광고)와 M-SEARCH 응답(200 OK)만. M-SEARCH 요청은 검색하는 쪽이라 장비 정보가 거의 없다.
            if (!first.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase) && !first.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)) return null;

            var facts = new List<Fact>();
            foreach (string line in lines.Skip(1))
            {
                int c = line.IndexOf(':');
                if (c <= 0) continue;
                string key = line[..c].Trim().ToUpperInvariant(), value = line[(c + 1)..].Trim();
                if (value.Length == 0) continue;
                switch (key)
                {
                    case "SERVER":
                        facts.Add(new Fact(FactFields.Service, value, SourceSsdp, Confidence.Low));
                        string? os = OsFromServerHeader(value);
                        if (os != null) facts.Add(new Fact(FactFields.Os, os, SourceSsdp, Confidence.Low));
                        break;
                    case "LOCATION":
                        facts.Add(new Fact(FactFields.Description, "UPnP " + value, SourceSsdp, Confidence.Low));
                        break;
                    case "NT":
                    case "ST":
                        string? dt = DeviceTypeFromUrn(value);
                        if (dt != null) facts.Add(new Fact(FactFields.DeviceType, dt, SourceSsdp, Confidence.Low));
                        break;
                }
            }
            if (facts.Count == 0) return null;
            return new HostObservation(srcIp, mac, SourceSsdp, Dedupe(facts), at);
        }

        private static string? OsFromServerHeader(string server)
        {
            if (server.Contains("Windows", StringComparison.OrdinalIgnoreCase)) return "Windows";
            if (server.Contains("Android", StringComparison.OrdinalIgnoreCase)) return "Android";
            if (server.Contains("Darwin", StringComparison.OrdinalIgnoreCase) || server.Contains("macOS", StringComparison.OrdinalIgnoreCase)) return "macOS";
            if (server.Contains("Linux", StringComparison.OrdinalIgnoreCase)) return "Linux";
            if (server.Contains("FreeBSD", StringComparison.OrdinalIgnoreCase)) return "FreeBSD";
            if (server.Contains("Roku", StringComparison.OrdinalIgnoreCase)) return "Roku OS";
            if (server.Contains("Tizen", StringComparison.OrdinalIgnoreCase)) return "Tizen";
            if (server.Contains("webOS", StringComparison.OrdinalIgnoreCase)) return "webOS";
            return null;
        }

        // "urn:schemas-upnp-org:device:MediaRenderer:1" → "MediaRenderer", "roku:ecp" → "roku"
        internal static string? DeviceTypeFromUrn(string nt)
        {
            if (nt.StartsWith("urn:", StringComparison.OrdinalIgnoreCase))
            {
                string[] parts = nt.Split(':');
                int i = Array.FindIndex(parts, p => p.Equals("device", StringComparison.OrdinalIgnoreCase));
                if (i >= 0 && i + 1 < parts.Length) return parts[i + 1];
                if (nt.Contains(":service:dial:", StringComparison.OrdinalIgnoreCase)) return "tv";
                return null;
            }
            if (nt.StartsWith("roku:", StringComparison.OrdinalIgnoreCase)) return "roku";
            return null; // upnp:rootdevice, uuid:… 는 종류 정보가 없다
        }

        internal static HostObservation? DecodeNetBios(byte[] payload, string srcIp, string mac, DateTimeOffset at)
        {
            if (srcIp.Length == 0 || payload.Length < 12 + 34) return null;
            try
            {
                int flags = (payload[2] << 8) | payload[3];
                bool isResponse = (flags & 0x8000) != 0;
                int opcode = (flags >> 11) & 0xF;
                // 등록(5), 갱신(8/9), 멀티홈 등록(15) 요청만. 질의 응답은 NetBiosProbe가 능동적으로 다룬다.
                if (isResponse || !(opcode is 5 or 8 or 9 or 15)) return null;
                int qd = (payload[4] << 8) | payload[5];
                int ar = (payload[10] << 8) | payload[11];
                if (qd < 1) return null;

                int pos = 12;
                if (!NetBiosCodec.TryReadEncodedName(payload, ref pos, out string name, out byte suffix)) return null;
                pos += 4; // qtype, qclass
                bool group = false;
                if (ar >= 1 && pos + 2 <= payload.Length)
                {
                    // RR 이름(포인터 2바이트 또는 전체) + type(2) class(2) ttl(4) rdlen(2) + NB_FLAGS(2)
                    if ((payload[pos] & 0xC0) == 0xC0) pos += 2;
                    else if (!NetBiosCodec.TryReadEncodedName(payload, ref pos, out _, out _)) return null;
                    pos += 10;
                    if (pos + 2 <= payload.Length) group = (payload[pos] & 0x80) != 0;
                }

                if (name.Length == 0 || name.StartsWith("\u0001\u0002__MSBROWSE__", StringComparison.Ordinal) || name.Any(char.IsControl)) return null;
                var facts = new List<Fact>();
                if (group)
                {
                    if (suffix is 0x00 or 0x1C or 0x1E) facts.Add(new Fact(FactFields.Domain, name, SourceNetBios, Confidence.Medium));
                }
                else if (suffix is 0x00 or 0x20 or 0x03)
                {
                    facts.Add(new Fact(FactFields.Name, name, SourceNetBios, Confidence.Medium));
                }
                if (facts.Count == 0) return null;
                return new HostObservation(srcIp, mac, SourceNetBios, facts, at);
            }
            catch
            {
                return null;
            }
        }

        private static HostObservation DecodeTcpSynAck(IPv4Packet ip, TcpPacket tcp, string mac, string srcIp, DateTimeOffset at)
        {
            byte[] opts = tcp.Options ?? Array.Empty<byte>();
            var sig = TcpSignature.FromOptions(ip.TimeToLive, tcp.WindowSize, opts);
            var facts = new List<Fact> { new(FieldTcpSignature, sig.ToString(), SourceTcp, Confidence.Low) };
            TcpFingerprints.Result? m = TcpFingerprints.Match(sig);
            if (m != null) facts.Add(new Fact(FactFields.Os, m.Os, SourceTcp, m.Confidence));
            return new HostObservation(srcIp, mac, SourceTcp, facts, at);
        }

        internal static string FormatMac(PhysicalAddress? addr)
        {
            if (addr == null) return "";
            byte[] b = addr.GetAddressBytes();
            return DhcpCodec.FormatMac(b);
        }

        private static IReadOnlyList<Fact> Dedupe(List<Fact> facts)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var result = new List<Fact>(facts.Count);
            foreach (Fact f in facts)
                if (seen.Add(f.Field + "\u0001" + f.Value)) result.Add(f);
            return result;
        }
    }
}
