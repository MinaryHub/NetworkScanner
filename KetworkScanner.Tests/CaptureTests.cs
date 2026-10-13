using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using KetworkScanner.Capture;
using KetworkScanner.Discovery;
using PacketDotNet;
using Xunit;

namespace KetworkScanner.Tests
{
    public class CaptureTests
    {
        private static readonly byte[] ClientMac = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
        private const string ClientMacText = "00:11:22:33:44:55";
        private static readonly byte[] WindowsParamList = { 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252 };

        // ---------- 원시 프레임 조립 도우미 (체크섬은 0; PacketDotNet은 파싱 시 검증하지 않는다) ----------

        private static byte[] Eth(byte[] src, byte[] dst, ushort type, byte[] payload)
        {
            var b = new List<byte>(14 + payload.Length);
            b.AddRange(dst); b.AddRange(src);
            b.Add((byte)(type >> 8)); b.Add((byte)type);
            b.AddRange(payload);
            return b.ToArray();
        }

        private static byte[] Ipv4(string src, string dst, byte proto, byte ttl, byte[] payload)
        {
            int total = 20 + payload.Length;
            var b = new List<byte>(total) { 0x45, 0, (byte)(total >> 8), (byte)total, 0x12, 0x34, 0x40, 0x00, ttl, proto, 0, 0 };
            b.AddRange(IPAddress.Parse(src).GetAddressBytes());
            b.AddRange(IPAddress.Parse(dst).GetAddressBytes());
            b.AddRange(payload);
            return b.ToArray();
        }

        private static byte[] Udp(ushort sp, ushort dp, byte[] payload)
        {
            int len = 8 + payload.Length;
            var b = new List<byte>(len) { (byte)(sp >> 8), (byte)sp, (byte)(dp >> 8), (byte)dp, (byte)(len >> 8), (byte)len, 0, 0 };
            b.AddRange(payload);
            return b.ToArray();
        }

        private static byte[] Tcp(ushort sp, ushort dp, ushort window, byte flags, byte[] options)
        {
            int optLen = (options.Length + 3) / 4 * 4;
            int hdr = 20 + optLen;
            var b = new List<byte>(hdr)
            {
                (byte)(sp >> 8), (byte)sp, (byte)(dp >> 8), (byte)dp,
                0, 0, 0, 1,          // seq
                0, 0, 0, 1,          // ack
                (byte)((hdr / 4) << 4), flags,
                (byte)(window >> 8), (byte)window,
                0, 0, 0, 0,          // checksum, urgent
            };
            b.AddRange(options);
            while (b.Count < hdr) b.Add(0);
            return b.ToArray();
        }

        private static byte[] UdpFrame(string srcIp, string dstIp, ushort sp, ushort dp, byte[] payload, byte[]? srcMac = null) =>
            Eth(srcMac ?? ClientMac, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 0x0800, Ipv4(srcIp, dstIp, 17, 64, Udp(sp, dp, payload)));

        // ---------- DHCP ----------

        [Fact]
        public void DhcpCodec_ParsesDiscover_HostnameVendorClassAndParamList()
        {
            byte[] payload = DhcpCodec.BuildRequest(1, ClientMac, "DESKTOP-7Q2", "MSFT 5.0", WindowsParamList);

            Assert.True(DhcpCodec.TryParse(payload, out DhcpMessage msg));
            Assert.True(msg.IsRequest);
            Assert.Equal(1, msg.MessageType);
            Assert.Equal(ClientMacText, msg.Mac);
            Assert.Equal("DESKTOP-7Q2", msg.Hostname);
            Assert.Equal("MSFT 5.0", msg.VendorClass);
            Assert.Equal("1,3,6,15,31,33,43,44,46,47,119,121,249,252", msg.Fingerprint);
            Assert.Equal("", msg.BestIp); // DISCOVER에는 IP가 없다
            Assert.NotNull(msg.ClientId);
        }

        [Fact]
        public void DhcpCodec_ParsesRequest_UsesRequestedIp()
        {
            byte[] payload = DhcpCodec.BuildRequest(3, ClientMac, "pixel", "android-dhcp-14", new byte[] { 1, 3, 6, 15, 26, 28, 51, 58, 59, 43 }, requestedIp: "192.168.1.77");
            Assert.True(DhcpCodec.TryParse(payload, out DhcpMessage msg));
            Assert.Equal(3, msg.MessageType);
            Assert.Equal("192.168.1.77", msg.BestIp);
            Assert.Equal("192.168.1.77", msg.RequestedIp);
        }

        [Fact]
        public void DhcpCodec_RejectsShortOrNonMagicPayload()
        {
            Assert.False(DhcpCodec.TryParse(new byte[50], out _));
            byte[] noCookie = DhcpCodec.BuildRequest(1, ClientMac, "x", null, null);
            noCookie[236] = 0; // magic cookie 훼손
            Assert.False(DhcpCodec.TryParse(noCookie, out _));
        }

        [Fact]
        public void DhcpFingerprints_ExactMatchIsHigh_PrefixMatchIsMedium_NoMatchIsNull()
        {
            DhcpFingerprints.Result? win = DhcpFingerprints.MatchList(WindowsParamList);
            Assert.NotNull(win);
            Assert.Equal("Windows 10/11", win!.Os);
            Assert.Equal(Confidence.High, win.Confidence);

            // macOS 목록 뒤에 옵션이 하나 더 붙은 경우 → 접두어 일치
            DhcpFingerprints.Result? mac = DhcpFingerprints.MatchFingerprint("1,121,3,6,15,119,252,95,44,46,47,101");
            Assert.NotNull(mac);
            Assert.Equal("macOS", mac!.Os);
            Assert.Equal(Confidence.Medium, mac.Confidence);

            Assert.Null(DhcpFingerprints.MatchFingerprint("9,8,7,6,5"));
            Assert.Null(DhcpFingerprints.MatchFingerprint("1,3"));   // 너무 짧아 접두어 판단 불가
            Assert.Null(DhcpFingerprints.MatchFingerprint(""));
        }

        [Fact]
        public void DhcpFingerprints_TableHasAtLeastTwelveDistinctEntries()
        {
            Assert.True(DhcpFingerprints.Table.Length >= 12);
            Assert.Equal(DhcpFingerprints.Table.Length, DhcpFingerprints.Table.Select(t => t.Fingerprint).Distinct().Count());
        }

        [Fact]
        public void DhcpFingerprints_VendorClassHints()
        {
            var win = DhcpFingerprints.FactsFromVendorClass("MSFT 5.0", "t");
            Assert.Contains(win, f => f.Field == FactFields.Os && f.Value == "Windows" && f.Confidence == Confidence.High);

            var android = DhcpFingerprints.FactsFromVendorClass("android-dhcp-14", "t");
            Assert.Contains(android, f => f.Field == FactFields.Os && f.Value == "Android 14" && f.Confidence == Confidence.High);

            var linux = DhcpFingerprints.FactsFromVendorClass("dhcpcd-9.4.1:Linux-6.1.0:x86_64:GenuineIntel", "t");
            Assert.Contains(linux, f => f.Field == FactFields.Os && f.Value == "Linux" && f.Confidence == Confidence.Medium);

            Assert.Empty(DhcpFingerprints.FactsFromVendorClass(null, "t"));
            Assert.Empty(DhcpFingerprints.FactsFromVendorClass("totally-unknown", "t"));
        }

        [Fact]
        public void Decode_DhcpDiscoverFrame_RecordsMacAndNameWithoutIp()
        {
            byte[] bootp = DhcpCodec.BuildRequest(1, ClientMac, "DESKTOP-7Q2", "MSFT 5.0", WindowsParamList);
            byte[] frame = UdpFrame("0.0.0.0", "255.255.255.255", 68, 67, bootp);

            HostObservation? obs = PassiveListener.Decode(frame, LinkLayers.Ethernet);

            Assert.NotNull(obs);
            Assert.Equal(PassiveListener.SourceDhcp, obs!.Source);
            Assert.Equal("", obs.Ip);
            Assert.Equal(ClientMacText, obs.Mac);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Name && f.Value == "DESKTOP-7Q2" && f.Confidence == Confidence.High);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Os && f.Value == "Windows" && f.Confidence == Confidence.High);
            Assert.Contains(obs.Facts, f => f.Field == PassiveListener.FieldDhcpFingerprint && f.Value == "1,3,6,15,31,33,43,44,46,47,119,121,249,252");
        }

        [Fact]
        public void Decode_DhcpRequestWithoutVendorClass_UsesFingerprintForOs()
        {
            byte[] bootp = DhcpCodec.BuildRequest(3, ClientMac, "iPhone", null, new byte[] { 1, 121, 3, 6, 15, 119, 252, 95, 44, 46 }, requestedIp: "10.0.0.9");
            HostObservation? obs = PassiveListener.Decode(UdpFrame("0.0.0.0", "255.255.255.255", 68, 67, bootp));
            Assert.NotNull(obs);
            Assert.Equal("10.0.0.9", obs!.Ip);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Os && f.Value == "macOS/iOS" && f.Confidence == Confidence.High);
        }

        // ---------- TCP ----------

        private static readonly byte[] AppleOpts = { 2, 4, 5, 0xB4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4, 2, 0 };
        private static readonly byte[] LinuxOpts = { 2, 4, 5, 0xB4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7 };
        private static readonly byte[] WindowsOpts = { 2, 4, 5, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2 };

        [Fact]
        public void TcpSignature_FromOptions_ParsesOrderAndValues()
        {
            var sig = TcpSignature.FromOptions(64, 65535, AppleOpts);
            Assert.Equal("mss,nop,wscale,nop,nop,ts,sack,eol", sig.OptionOrder);
            Assert.Equal(1460, sig.Mss);
            Assert.Equal(6, sig.WindowScale);
            Assert.True(sig.SackOk);
            Assert.True(sig.Timestamps);
            Assert.Equal("64:65535:1460:6:1:1:mss,nop,wscale,nop,nop,ts,sack,eol", sig.ToString());
        }

        [Fact]
        public void TcpFingerprints_MatchesMacLinuxWindowsAndCisco()
        {
            var apple = TcpFingerprints.Match(new TcpSignature(64, 65535, 1460, 6, true, true, "mss,nop,wscale,nop,nop,ts,sack,eol"));
            Assert.Equal("macOS/iOS", apple?.Os);

            var linux = TcpFingerprints.Match(new TcpSignature(64, 64240, 1460, 7, true, true, "mss,sack,ts,nop,wscale"));
            Assert.Equal("Linux", linux?.Os);
            Assert.Equal(Confidence.Medium, linux!.Confidence);

            var windows = TcpFingerprints.Match(new TcpSignature(128, 8192, 1460, 8, true, false, "mss,nop,wscale,nop,nop,sack"));
            Assert.Equal("Windows", windows?.Os);
            Assert.Equal(Confidence.Medium, windows!.Confidence);

            var cisco = TcpFingerprints.Match(new TcpSignature(255, 4128, 536, -1, false, false, "mss"));
            Assert.Equal("Cisco IOS", cisco?.Os);

            var oldLinux = TcpFingerprints.Match(new TcpSignature(64, 5840, 1460, -1, false, false, "mss"));
            Assert.Equal("Linux 2.6 (old)", oldLinux?.Os);

            Assert.Null(TcpFingerprints.Match(new TcpSignature(200, 12345, 0, -1, false, false, "opt99,opt98")));
        }

        [Fact]
        public void Decode_TcpSynAckFrame_GivesOsGuessAndRespectsOnLinkMacRule()
        {
            byte[] tcp = Tcp(443, 51000, 29200, 0x12 /* SYN|ACK */, LinuxOpts);
            byte[] frame = Eth(ClientMac, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, 0x0800, Ipv4("192.168.1.20", "192.168.1.2", 6, 64, tcp));

            HostObservation? obs = PassiveListener.Decode(frame, LinkLayers.Ethernet);
            Assert.NotNull(obs);
            Assert.Equal(PassiveListener.SourceTcp, obs!.Source);
            Assert.Equal("192.168.1.20", obs.Ip);
            Assert.Equal(ClientMacText, obs.Mac);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Os && f.Value == "Linux" && f.Confidence == Confidence.Medium);
            Assert.Contains(obs.Facts, f => f.Field == PassiveListener.FieldTcpSignature && f.Value.StartsWith("64:29200:1460:7:1:1:", StringComparison.Ordinal));

            // 캡처 인터페이스가 10.0.0.0/24이면 192.168.1.20은 라우팅된 호스트 → 이더넷 MAC(게이트웨이)을 믿지 않는다.
            HostObservation? routed = PassiveListener.Decode(frame, LinkLayers.Ethernet, DateTimeOffset.UtcNow, (0x0A000000u, 0xFFFFFF00u));
            Assert.Equal("", routed!.Mac);

            // SYN만(ACK 없음)인 패킷은 무시
            byte[] synOnly = Eth(ClientMac, ClientMac, 0x0800, Ipv4("192.168.1.20", "192.168.1.2", 6, 64, Tcp(51000, 443, 65535, 0x02, WindowsOpts)));
            Assert.Null(PassiveListener.Decode(synOnly));
        }

        // ---------- ARP ----------

        private static byte[] BuildArpFrame(ArpOperation op, string senderIp, byte[] senderMac, string targetIp)
        {
            var sender = new PhysicalAddress(senderMac);
            var bcast = new PhysicalAddress(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            var zero = new PhysicalAddress(new byte[6]);
            var arp = new ArpPacket(op, zero, IPAddress.Parse(targetIp), sender, IPAddress.Parse(senderIp));
            var eth = new EthernetPacket(sender, bcast, EthernetType.Arp) { PayloadPacket = arp };
            return eth.Bytes;
        }

        [Fact]
        public void Decode_ArpRequestAndReply_FromPacketDotNetBuiltFrames()
        {
            HostObservation? req = PassiveListener.Decode(BuildArpFrame(ArpOperation.Request, "192.168.1.10", ClientMac, "192.168.1.1"), LinkLayers.Ethernet);
            Assert.NotNull(req);
            Assert.Equal(PassiveListener.SourceArp, req!.Source);
            Assert.Equal("192.168.1.10", req.Ip);
            Assert.Equal(ClientMacText, req.Mac);
            Assert.Contains(req.Facts, f => f.Field == FactFields.Mac && f.Value == ClientMacText && f.Confidence == Confidence.High);

            HostObservation? reply = PassiveListener.Decode(BuildArpFrame(ArpOperation.Response, "192.168.1.1", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, "192.168.1.10"));
            Assert.Equal("192.168.1.1", reply!.Ip);
            Assert.Equal("DE:AD:BE:EF:00:01", reply.Mac);

            // Gratuitous ARP(보낸 IP == 대상 IP)도 그대로 기록
            HostObservation? grat = PassiveListener.Decode(BuildArpFrame(ArpOperation.Request, "192.168.1.50", ClientMac, "192.168.1.50"));
            Assert.Equal("192.168.1.50", grat!.Ip);

            // ARP probe(보낸 IP 0.0.0.0)는 MAC만
            HostObservation? probe = PassiveListener.Decode(BuildArpFrame(ArpOperation.Request, "0.0.0.0", ClientMac, "192.168.1.60"));
            Assert.NotNull(probe);
            Assert.Equal("", probe!.Ip);
            Assert.Equal(ClientMacText, probe.Mac);
        }

        [Fact]
        public void Decode_GarbageAndUnknownLinkType_ReturnsNullWithoutThrowing()
        {
            Assert.Null(PassiveListener.Decode(new byte[] { 1, 2, 3 }, LinkLayers.Ethernet));
            Assert.Null(PassiveListener.Decode(Array.Empty<byte>(), LinkLayers.Ethernet));
            Assert.Null(PassiveListener.Decode(new byte[64], LinkLayers.Ethernet)); // EtherType 0 → IP/ARP 아님
        }

        // ---------- mDNS ----------

        private static void DnsName(List<byte> b, string name)
        {
            foreach (string label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                b.Add((byte)label.Length);
                b.AddRange(Encoding.ASCII.GetBytes(label));
            }
            b.Add(0);
        }

        private static void DnsRecord(List<byte> b, string name, ushort type, byte[] rdata)
        {
            DnsName(b, name);
            b.Add((byte)(type >> 8)); b.Add((byte)type);
            b.Add(0x80); b.Add(0x01);          // IN, cache-flush
            b.AddRange(new byte[] { 0, 0, 0x11, 0x94 });
            b.Add((byte)(rdata.Length >> 8)); b.Add((byte)rdata.Length);
            b.AddRange(rdata);
        }

        private static byte[] TxtRdata(params string[] entries)
        {
            var b = new List<byte>();
            foreach (string e in entries) { b.Add((byte)e.Length); b.AddRange(Encoding.ASCII.GetBytes(e)); }
            return b.ToArray();
        }

        [Fact]
        public void Decode_MdnsResponse_NameFromARecordAndModelFromTxt()
        {
            var b = new List<byte> { 0, 0, 0x84, 0x00, 0, 0, 0, 3, 0, 0, 0, 0 }; // QR=1 AA=1, 3 answers
            DnsRecord(b, "Kims-MacBook.local", 1, IPAddress.Parse("192.168.1.5").GetAddressBytes());
            DnsRecord(b, "Kims-MacBook._device-info._tcp.local", 16, TxtRdata("model=MacBookPro18,3", "osxvers=23"));
            DnsRecord(b, "_airplay._tcp.local", 12, Array.Empty<byte>());
            byte[] frame = UdpFrame("192.168.1.5", "224.0.0.251", 5353, 5353, b.ToArray());

            HostObservation? obs = PassiveListener.Decode(frame);
            Assert.NotNull(obs);
            Assert.Equal(PassiveListener.SourceMdns, obs!.Source);
            Assert.Equal("192.168.1.5", obs.Ip);
            Assert.Equal(ClientMacText, obs.Mac);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Name && f.Value == "Kims-MacBook" && f.Confidence == Confidence.Medium);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Model && f.Value == "MacBookPro18,3");
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Os && f.Value == "macOS");
            Assert.Contains(obs.Facts, f => f.Field == FactFields.DeviceType && f.Value == "media");
        }

        [Fact]
        public void Decode_MdnsQuery_IsIgnored()
        {
            var b = new List<byte> { 0, 0, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
            DnsName(b, "_services._dns-sd._udp.local"); b.AddRange(new byte[] { 0, 12, 0, 1 });
            Assert.Null(PassiveListener.Decode(UdpFrame("192.168.1.5", "224.0.0.251", 5353, 5353, b.ToArray())));
        }

        // ---------- SSDP ----------

        [Fact]
        public void Decode_SsdpNotify_ServerLocationAndNt()
        {
            string notify = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n" +
                            "SERVER: Linux/4.9 UPnP/1.0 Samsung-TV/1.0\r\nLOCATION: http://192.168.1.30:9197/dmr\r\nNTS: ssdp:alive\r\n\r\n";
            byte[] frame = UdpFrame("192.168.1.30", "239.255.255.250", 40000, 1900, Encoding.ASCII.GetBytes(notify));

            HostObservation? obs = PassiveListener.Decode(frame);
            Assert.NotNull(obs);
            Assert.Equal(PassiveListener.SourceSsdp, obs!.Source);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Service && f.Value.Contains("Samsung-TV") && f.Confidence == Confidence.Low);
            Assert.Contains(obs.Facts, f => f.Field == FactFields.DeviceType && f.Value == "MediaRenderer");
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Os && f.Value == "Linux");
            Assert.Contains(obs.Facts, f => f.Field == FactFields.Description && f.Value.Contains("http://192.168.1.30:9197/dmr"));

            // M-SEARCH 요청은 무시
            byte[] msearch = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n");
            Assert.Null(PassiveListener.Decode(UdpFrame("192.168.1.31", "239.255.255.250", 40001, 1900, msearch)));
        }

        [Fact]
        public void DeviceTypeFromUrn_ParsesDeviceAndRoku()
        {
            Assert.Equal("MediaRenderer", PassiveListener.DeviceTypeFromUrn("urn:schemas-upnp-org:device:MediaRenderer:1"));
            Assert.Equal("roku", PassiveListener.DeviceTypeFromUrn("roku:ecp"));
            Assert.Null(PassiveListener.DeviceTypeFromUrn("upnp:rootdevice"));
        }

        // ---------- NetBIOS ----------

        private static byte[] NbRegistration(string name, byte suffix, bool group)
        {
            var raw = new byte[16];
            byte[] n = Encoding.ASCII.GetBytes(name.PadRight(15));
            Array.Copy(n, raw, 15); raw[15] = suffix;
            var b = new List<byte> { 0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1 }; // opcode 5(registration), broadcast
            b.Add(32);
            foreach (byte x in raw) { b.Add((byte)('A' + (x >> 4))); b.Add((byte)('A' + (x & 0xF))); }
            b.Add(0);
            b.AddRange(new byte[] { 0, 0x20, 0, 1 });                 // NB, IN
            b.AddRange(new byte[] { 0xC0, 0x0C, 0, 0x20, 0, 1, 0, 0, 0x0E, 0x10, 0, 6 });
            b.Add((byte)(group ? 0x80 : 0x00)); b.Add(0);             // NB_FLAGS
            b.AddRange(IPAddress.Parse("192.168.1.40").GetAddressBytes());
            return b.ToArray();
        }

        [Fact]
        public void Decode_NetBiosRegistration_NameAndWorkgroup()
        {
            HostObservation? host = PassiveListener.Decode(UdpFrame("192.168.1.40", "192.168.1.255", 137, 137, NbRegistration("MYPC", 0x00, false)));
            Assert.NotNull(host);
            Assert.Equal(PassiveListener.SourceNetBios, host!.Source);
            Assert.Contains(host.Facts, f => f.Field == FactFields.Name && f.Value == "MYPC" && f.Confidence == Confidence.Medium);

            HostObservation? wg = PassiveListener.Decode(UdpFrame("192.168.1.40", "192.168.1.255", 137, 137, NbRegistration("WORKGROUP", 0x1E, true)));
            Assert.NotNull(wg);
            Assert.Contains(wg!.Facts, f => f.Field == FactFields.Domain && f.Value == "WORKGROUP");
        }

        // ---------- Aggregator ----------

        private static HostObservation Obs(string ip, string mac, string source, DateTimeOffset at, params Fact[] facts) =>
            new(ip, mac, source, facts, at);

        [Fact]
        public void Aggregator_MergesSourcesPerIp_AndNewestWinsTie()
        {
            var agg = new ObservationAggregator();
            DateTimeOffset t0 = new(2026, 10, 12, 9, 0, 0, TimeSpan.Zero);
            agg.Add(Obs("10.0.0.5", "AA:BB:CC:00:00:01", "pcap-dhcp", t0, new Fact(FactFields.Name, "old-name", "pcap-dhcp", Confidence.High)));
            agg.Add(Obs("10.0.0.5", "", "pcap-tcp", t0.AddSeconds(1), new Fact(FactFields.Os, "Linux", "pcap-tcp", Confidence.Medium)));
            agg.Add(Obs("10.0.0.5", "AA:BB:CC:00:00:01", "pcap-dhcp", t0.AddSeconds(2), new Fact(FactFields.Name, "new-name", "pcap-dhcp", Confidence.High)));
            // 같은 출처의 더 오래된 관찰이 늦게 와도 무시
            agg.Add(Obs("10.0.0.5", "AA:BB:CC:00:00:01", "pcap-dhcp", t0.AddSeconds(-5), new Fact(FactFields.Name, "stale", "pcap-dhcp", Confidence.High)));

            var (byIp, byMac) = agg.Snapshot();
            Assert.Equal(1, agg.IpCount);
            Assert.Equal(1, agg.MacCount);
            Assert.Equal(4, agg.ObservationCount);
            HostFacts h = byIp["10.0.0.5"];
            Assert.Equal("new-name", h.BestValue(FactFields.Name));
            Assert.Equal("Linux", h.BestValue(FactFields.Os));
            Assert.Equal("AA:BB:CC:00:00:01", h.BestValue(FactFields.Mac));
            Assert.DoesNotContain(h.All, f => f.Value == "stale");
            Assert.Equal("10.0.0.5", byMac["AA:BB:CC:00:00:01"].Ip);
            Assert.Equal(t0.AddSeconds(2), agg.LastSeenByIp("10.0.0.5"));
        }

        [Fact]
        public void Aggregator_JoinsIpLessObservationByMac()
        {
            var agg = new ObservationAggregator();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            // DHCP DISCOVER: IP 없이 MAC + 이름
            agg.Add(Obs("", "AA:BB:CC:00:00:02", "pcap-dhcp", now, new Fact(FactFields.Name, "pc-discover", "pcap-dhcp", Confidence.High)));
            Assert.Equal(0, agg.IpCount);
            Assert.Null(agg.IpOfMac("AA:BB:CC:00:00:02"));
            // 나중에 ARP가 MAC ↔ IP를 묶어준다
            agg.Add(Obs("10.0.0.9", "aa:bb:cc:00:00:02", "pcap-arp", now.AddSeconds(1), new Fact(FactFields.Mac, "AA:BB:CC:00:00:02", "pcap-arp", Confidence.High)));

            var (byIp, _) = agg.Snapshot();
            Assert.Equal("pc-discover", byIp["10.0.0.9"].BestValue(FactFields.Name));
            Assert.Equal("10.0.0.9", agg.IpOfMac("AA:BB:CC:00:00:02"));
            // IP도 MAC도 없는 관찰은 버린다
            agg.Add(Obs("", "", "pcap-tcp", now));
            Assert.Equal(1, agg.IpCount);
        }

        [Fact]
        public void Aggregator_PruneDropsStaleHosts()
        {
            var agg = new ObservationAggregator();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            agg.Add(Obs("10.0.0.1", "AA:BB:CC:00:00:11", "pcap-arp", now.AddHours(-2)));
            agg.Add(Obs("10.0.0.2", "AA:BB:CC:00:00:12", "pcap-arp", now));

            int removed = agg.Prune(TimeSpan.FromHours(1), now);
            Assert.Equal(2, removed); // IP 항목 1 + MAC 항목 1
            var (byIp, byMac) = agg.Snapshot();
            Assert.False(byIp.ContainsKey("10.0.0.1"));
            Assert.True(byIp.ContainsKey("10.0.0.2"));
            Assert.Single(byMac);

            agg.Clear();
            Assert.Equal(0, agg.IpCount);
        }

        [Fact]
        public void Aggregator_IsSafeUnderConcurrentAdds()
        {
            var agg = new ObservationAggregator();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            System.Threading.Tasks.Parallel.For(0, 2000, i =>
            {
                string ip = "10.1." + (i % 50) + "." + (i % 7);
                agg.Add(Obs(ip, "AA:BB:CC:" + (i % 50).ToString("X2") + ":00:00", i % 2 == 0 ? "pcap-arp" : "pcap-tcp", now.AddMilliseconds(i),
                    new Fact(FactFields.Os, "Linux", "pcap-tcp", Confidence.Medium)));
                if (i % 100 == 0) agg.Snapshot();
            });
            Assert.Equal(2000, agg.ObservationCount);
            Assert.True(agg.IpCount > 0);
        }

        // ---------- 리스너 수명주기 / 환경 ----------

        [Fact]
        public void Probe_ReturnsTupleWithoutThrowing()
        {
            var (available, reason) = PassiveListener.Probe();
            Assert.False(string.IsNullOrWhiteSpace(reason));
            // 결과는 머신(libpcap/권한)에 따라 다르다. 내용만 출력해 둔다.
            Console.WriteLine($"PassiveListener.Probe(): available={available} reason={reason}");
        }

        [Fact]
        public void Start_OnUnknownInterface_FailsGracefully_AndStopIsIdempotent()
        {
            using var listener = new PassiveListener("no-such-interface-zz9");
            bool started = listener.Start();
            Assert.False(started);
            Assert.False(listener.IsAvailable);
            Assert.False(listener.IsRunning);
            Assert.False(string.IsNullOrWhiteSpace(listener.UnavailableReason));
            listener.Stop();
            listener.Stop();
            listener.Dispose();
        }

        [Fact]
        public void ExplainFailure_DistinguishesMissingLibraryFromPermission()
        {
            string lib = PassiveListener.ExplainFailure(new TypeInitializationException("X", new DllNotFoundException("wpcap")));
            Assert.Contains("라이브러리", lib);
            string perm = PassiveListener.ExplainFailure(new InvalidOperationException("(cannot open BPF device) /dev/bpf0: Permission denied"));
            Assert.Contains("권한", perm);
            string other = PassiveListener.ExplainFailure(new InvalidOperationException("weird"));
            Assert.Contains("weird", other);
        }

        [Fact]
        public void Filter_IsTheAgreedBpfExpression()
        {
            Assert.Equal("arp or (udp and (port 67 or port 68 or port 5353 or port 1900 or port 137)) or (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))", PassiveListener.Filter);
        }
    }
}
