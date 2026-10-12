using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Discovery;
using NetworkScanner.Discovery.Multicast;

namespace NetworkScanner.Tests
{
    public class MulticastDiscoveryTests
    {
        // ---------- 테스트용 DNS 메시지 인코더(이름 압축 포함) ----------

        // 응답 메시지를 조립한다. 같은 접미사가 다시 나오면 압축 포인터(0xC0xx)를 쓴다.
        private sealed class DnsMessageBuilder
        {
            private readonly List<byte> _buf = new();
            private readonly Dictionary<string, int> _suffixOffsets = new(StringComparer.OrdinalIgnoreCase);
            private int _answers;

            public DnsMessageBuilder(ushort id = 0, ushort flags = 0x8400)
            {
                U16(id); U16(flags); U16(0); U16(0); U16(0); U16(0);
            }

            public DnsMessageBuilder Ptr(string name, string target) => Record(name, DnsCodec.TypePtr, () => Name(target));
            public DnsMessageBuilder A(string name, string ip) => Record(name, DnsCodec.TypeA, () => _buf.AddRange(IPAddress.Parse(ip).GetAddressBytes()));
            public DnsMessageBuilder Aaaa(string name, string ip) => Record(name, DnsCodec.TypeAaaa, () => _buf.AddRange(IPAddress.Parse(ip).GetAddressBytes()));
            public DnsMessageBuilder Srv(string name, int port, string target) => Record(name, DnsCodec.TypeSrv, () => { U16(0); U16(0); U16((ushort)port); Name(target); });
            public DnsMessageBuilder Txt(string name, params string[] kvs) => Record(name, DnsCodec.TypeTxt, () =>
            {
                foreach (string kv in kvs)
                {
                    byte[] b = Encoding.UTF8.GetBytes(kv);
                    _buf.Add((byte)b.Length); _buf.AddRange(b);
                }
            });

            private DnsMessageBuilder Record(string name, ushort type, Action rdata)
            {
                Name(name);
                U16(type); U16(DnsCodec.ClassIn | 0x8000 /* cache-flush 비트도 섞어 본다 */);
                U16(0); U16(120);
                int lenPos = _buf.Count; U16(0);
                int start = _buf.Count;
                rdata();
                int len = _buf.Count - start;
                _buf[lenPos] = (byte)(len >> 8); _buf[lenPos + 1] = (byte)len;
                _answers++;
                return this;
            }

            private void Name(string name)
            {
                string[] labels = name.TrimEnd('.').Split('.');
                for (int i = 0; i < labels.Length; i++)
                {
                    string suffix = string.Join(".", labels.Skip(i));
                    if (_suffixOffsets.TryGetValue(suffix, out int off))
                    {
                        _buf.Add((byte)(0xC0 | (off >> 8))); _buf.Add((byte)off);
                        return;
                    }
                    if (_buf.Count < 0x3FFF) _suffixOffsets[suffix] = _buf.Count;
                    byte[] b = Encoding.UTF8.GetBytes(labels[i]);
                    _buf.Add((byte)b.Length); _buf.AddRange(b);
                }
                _buf.Add(0);
            }

            private void U16(int v) { _buf.Add((byte)(v >> 8)); _buf.Add((byte)v); }

            public byte[] Build()
            {
                _buf[6] = (byte)(_answers >> 8); _buf[7] = (byte)_answers;
                return _buf.ToArray();
            }

            public DnsCodec.Response Parse()
            {
                Assert.True(DnsCodec.TryParseResponse(Build(), out DnsCodec.Response r));
                return r;
            }
        }

        private static Fact? Best(IReadOnlyList<Fact> facts, string field)
            => facts.Where(f => f.Field == field).OrderByDescending(f => (int)f.Confidence).FirstOrDefault();

        // ---------- SSDP: 헤더 ----------

        private const string SampleSsdp =
            "HTTP/1.1 200 OK\r\n" +
            "CACHE-CONTROL: max-age=1800\r\n" +
            "EXT:\r\n" +
            "LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n" +
            "SERVER: Linux/3.14.0 UPnP/1.0 MiniUPnPd/2.1\r\n" +
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
            "USN: uuid:12345678-0000-0000-0000-000000000001::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
            "\r\n";

        [Fact]
        public void Ssdp_ParseResponse_ReadsStatusAndHeadersCaseInsensitively()
        {
            SsdpDiscovery.SsdpResponse? r = SsdpDiscovery.ParseResponse(Encoding.ASCII.GetBytes(SampleSsdp));
            Assert.NotNull(r);
            Assert.True(r!.IsOk);
            Assert.Equal("http://192.168.1.1:5000/rootDesc.xml", r.Get("location"));
            Assert.Equal("Linux/3.14.0 UPnP/1.0 MiniUPnPd/2.1", r.Get("Server"));
            Assert.Equal("", r.Get("EXT"));
            Assert.Null(r.Get("missing"));
            Assert.Null(SsdpDiscovery.ParseResponse(Array.Empty<byte>()));
            Assert.False(SsdpDiscovery.ParseResponse("HTTP/1.1 404 Not Found\r\n\r\n")!.IsOk);
        }

        [Fact]
        public void Ssdp_Accumulate_MergesPerIpAndIgnoresNon200()
        {
            var hosts = new Dictionary<string, SsdpHost>();
            IPAddress ip = IPAddress.Parse("192.168.1.1");
            SsdpDiscovery.Accumulate(hosts, ip, Encoding.ASCII.GetBytes(SampleSsdp));
            SsdpDiscovery.Accumulate(hosts, ip, Encoding.ASCII.GetBytes(SampleSsdp.Replace("InternetGatewayDevice:1", "WANConnectionDevice:1")));
            SsdpDiscovery.Accumulate(hosts, ip, Encoding.ASCII.GetBytes("HTTP/1.1 503 Busy\r\nSERVER: x\r\n\r\n"));
            SsdpDiscovery.Accumulate(hosts, ip, new byte[] { 0xFF, 0x00 });

            SsdpHost h = Assert.Single(hosts).Value;
            Assert.Single(h.Servers);
            Assert.Single(h.Locations);
            Assert.Equal(4, h.SearchTargets.Count);   // ST+USN × 2

            IReadOnlyList<Fact> facts = SsdpDiscovery.FactsFromHost(h);
            Assert.Equal("Linux", Best(facts, FactFields.Os)!.Value);
            Assert.Equal("router", Best(facts, FactFields.DeviceType)!.Value);
            Assert.Equal("Linux/3.14.0 UPnP/1.0 MiniUPnPd/2.1", Best(facts, FactFields.Service)!.Value);
            Assert.All(facts, f => Assert.Equal("SSDP", f.Source));
        }

        [Theory]
        [InlineData("Linux/3.x UPnP/1.0 Synology/1.0", "Linux", "Synology", "nas")]
        [InlineData("Windows/10.0 UPnP/1.0 Microsoft-DLNA-DOC/1.0", "Windows", null, null)]
        [InlineData("Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0", "Windows", null, null)]
        [InlineData("Linux UPnP/1.0 Sonos/80.2-1 (ZPS9)", "Linux", "Sonos", "media")]
        [InlineData("KODAK/1.0 UPnP/1.0", null, "Kodak", "printer")]
        [InlineData("Ubuntu/22.04 UPnP/1.0 MiniDLNA/1.3", "Linux", null, null)]
        public void Ssdp_FactsFromServerHeader_FindsOsAndVendor(string server, string? os, string? vendor, string? type)
        {
            IReadOnlyList<Fact> facts = SsdpDiscovery.FactsFromServerHeader(server);
            Assert.Equal(os, Best(facts, FactFields.Os)?.Value);
            Assert.Equal(vendor, Best(facts, FactFields.Vendor)?.Value);
            Assert.Equal(type, Best(facts, FactFields.DeviceType)?.Value);
        }

        [Fact]
        public void Ssdp_FactsFromServerHeader_WindowsVersionBecomesOsVersion()
        {
            IReadOnlyList<Fact> facts = SsdpDiscovery.FactsFromServerHeader("Windows/10.0 UPnP/1.0");
            Assert.Equal("Windows 10.0", Best(facts, FactFields.OsVersion)!.Value);
            Assert.Equal("Ubuntu 22.04", Best(SsdpDiscovery.FactsFromServerHeader("Ubuntu/22.04 UPnP/1.0"), FactFields.OsVersion)!.Value);
            Assert.Empty(SsdpDiscovery.FactsFromServerHeader("   "));
        }

        [Theory]
        [InlineData("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "router")]
        [InlineData("uuid:abc::urn:schemas-upnp-org:service:WANIPConnection:1", "router")]
        [InlineData("urn:schemas-upnp-org:device:MediaRenderer:1", "media")]
        [InlineData("urn:schemas-upnp-org:device:MediaServer:1", "nas/media server")]
        [InlineData("urn:schemas-upnp-org:device:Printer:1", "printer")]
        [InlineData("urn:schemas-upnp-org:device:Basic:1", "iot")]
        [InlineData("urn:dial-multiscreen-org:service:dial:1", "media")]
        [InlineData("roku:ecp", "media")]
        [InlineData("upnp:rootdevice", null)]
        [InlineData("uuid:12345678-0000-0000-0000-000000000001", null)]
        [InlineData("", null)]
        [InlineData(null, null)]
        public void Ssdp_MapDeviceType_MapsKnownUpnpTypes(string? upnp, string? expected)
        {
            Assert.Equal(expected, SsdpDiscovery.MapDeviceType(upnp));
        }

        [Fact]
        public void Ssdp_IsLocationForHost_OnlyAcceptsHttpToRespondingIp()
        {
            Assert.True(SsdpDiscovery.IsLocationForHost("http://192.168.1.1:5000/rootDesc.xml", "192.168.1.1", out Uri? u));
            Assert.Equal(5000, u!.Port);
            Assert.True(SsdpDiscovery.IsLocationForHost(" https://192.168.1.1/desc.xml ", "192.168.1.1", out _));
            Assert.False(SsdpDiscovery.IsLocationForHost("http://192.168.1.2/rootDesc.xml", "192.168.1.1", out _));
            Assert.False(SsdpDiscovery.IsLocationForHost("http://evil.example.com/x.xml", "192.168.1.1", out _));
            Assert.False(SsdpDiscovery.IsLocationForHost("ftp://192.168.1.1/x.xml", "192.168.1.1", out _));
            Assert.False(SsdpDiscovery.IsLocationForHost("not a url", "192.168.1.1", out _));
        }

        // ---------- SSDP: 장비 설명 XML ----------

        private const string SampleDescription = @"<?xml version=""1.0""?>
<root xmlns=""urn:schemas-upnp-org:device-1-0"">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType>
    <friendlyName>HP LaserJet (3F2A1C)</friendlyName>
    <manufacturer>HP</manufacturer>
    <modelDescription>HP LaserJet Pro MFP</modelDescription>
    <modelName>HP LaserJet Pro MFP M428fdw</modelName>
    <modelNumber>W1A30A</modelNumber>
    <serialNumber>VNB3K12345</serialNumber>
    <UDN>uuid:1ab2c3d4-0000-1000-8000-aabbcc3f2a1c</UDN>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
        <friendlyName>embedded</friendlyName>
      </device>
    </deviceList>
  </device>
</root>";

        [Fact]
        public void Ssdp_ParseDeviceDescription_ReadsRootDeviceOnly()
        {
            SsdpDiscovery.DeviceDescription? d = SsdpDiscovery.ParseDeviceDescription(SampleDescription);
            Assert.NotNull(d);
            Assert.Equal("HP LaserJet (3F2A1C)", d!.FriendlyName);     // 하위 장비 "embedded"가 아님
            Assert.Equal("HP", d.Manufacturer);
            Assert.Equal("HP LaserJet Pro MFP M428fdw", d.ModelName);
            Assert.Equal("W1A30A", d.ModelNumber);
            Assert.Equal("VNB3K12345", d.SerialNumber);
            Assert.Equal("urn:schemas-upnp-org:device:Printer:1", d.DeviceType);

            IReadOnlyList<Fact> facts = SsdpDiscovery.FactsFromDescription(d);
            Assert.Equal(("HP LaserJet (3F2A1C)", Confidence.Medium), (Best(facts, FactFields.Name)!.Value, Best(facts, FactFields.Name)!.Confidence));
            Assert.Equal(("HP", Confidence.High), (Best(facts, FactFields.Vendor)!.Value, Best(facts, FactFields.Vendor)!.Confidence));
            Assert.Equal(("HP LaserJet Pro MFP M428fdw W1A30A", Confidence.High), (Best(facts, FactFields.Model)!.Value, Best(facts, FactFields.Model)!.Confidence));
            Assert.Equal(("VNB3K12345", Confidence.Medium), (Best(facts, FactFields.Serial)!.Value, Best(facts, FactFields.Serial)!.Confidence));
            Assert.Equal("printer", Best(facts, FactFields.DeviceType)!.Value);
        }

        [Fact]
        public void Ssdp_ParseDeviceDescription_RejectsGarbageAndDtd()
        {
            Assert.Null(SsdpDiscovery.ParseDeviceDescription("<html><body>not upnp</body></html>"));
            Assert.Null(SsdpDiscovery.ParseDeviceDescription("<<<broken"));
            Assert.Null(SsdpDiscovery.ParseDeviceDescription(""));
            Assert.Null(SsdpDiscovery.ParseDeviceDescription("<!DOCTYPE root [<!ENTITY x \"y\">]><root><device><friendlyName>&x;</friendlyName></device></root>"));
        }

        [Fact]
        public void Ssdp_FactsFromHost_DescriptionBeatsHeadersAtSameConfidence()
        {
            var h = new SsdpHost("192.168.1.9");
            h.Servers.Add("Linux/4.4 UPnP/1.0 Synology/1.0");
            h.SearchTargets.Add("urn:schemas-upnp-org:device:MediaServer:1");
            h.Descriptions.Add(SsdpDiscovery.ParseDeviceDescription(SampleDescription.Replace("HP", "Synology Inc.").Replace("Printer:1", "MediaServer:1"))!);
            IReadOnlyList<Fact> facts = SsdpDiscovery.FactsFromHost(h);
            Assert.Equal("Synology Inc.", Best(facts, FactFields.Vendor)!.Value);        // High (XML) > Medium (헤더)
            Assert.Equal("nas/media server", Best(facts, FactFields.DeviceType)!.Value);  // High (XML deviceType)
        }

        // ---------- mDNS ----------

        [Fact]
        public void Mdns_FactsFromResponses_AppleTvAndMacFromCompressedMessage()
        {
            // Apple TV: PTR → SRV/TXT → A, 모두 한 패킷(압축 포인터 사용)
            DnsCodec.Response appleTv = new DnsMessageBuilder()
                .Ptr("_airplay._tcp.local", "Living Room._airplay._tcp.local")
                .Srv("Living Room._airplay._tcp.local", 7000, "Apple-TV.local")
                .Txt("Living Room._airplay._tcp.local", "model=AppleTV6,2", "deviceid=A8:5B:78:11:22:33", "srcvers=670.6.2")
                .A("Apple-TV.local", "192.168.1.50")
                .Aaaa("Apple-TV.local", "fe80::1")
                .Parse();
            // Mac: _device-info(SRV 없음)와 _smb, A는 별도 패킷
            DnsCodec.Response mac1 = new DnsMessageBuilder()
                .Txt("Kims-MBP._device-info._tcp.local", "model=MacBookPro18,3", "osxvers=23")
                .Ptr("_smb._tcp.local", "Kims-MBP._smb._tcp.local")
                .Srv("Kims-MBP._smb._tcp.local", 445, "Kims-MBP.local")
                .Parse();
            DnsCodec.Response mac2 = new DnsMessageBuilder().A("Kims-MBP.local", "192.168.1.20").Parse();

            // 압축이 실제로 쓰였는지(포인터 바이트가 있는지) 확인
            byte[] raw = new DnsMessageBuilder().Ptr("_airplay._tcp.local", "x._airplay._tcp.local").Build();
            Assert.Contains(raw, b => (b & 0xC0) == 0xC0);

            IReadOnlyDictionary<string, IReadOnlyList<Fact>> all = MdnsBrowser.FactsFromResponses(new[] { appleTv, mac1, mac2 });
            Assert.Equal(2, all.Count);

            IReadOnlyList<Fact> tv = all["192.168.1.50"];
            Assert.Equal(("Apple-TV", Confidence.High), (Best(tv, FactFields.Name)!.Value, Best(tv, FactFields.Name)!.Confidence));
            Assert.Equal("Apple TV 4K (1st gen)", Best(tv, FactFields.Model)!.Value);
            Assert.Contains(tv, f => f.Field == FactFields.Model && f.Value == "AppleTV6,2" && f.Confidence == Confidence.Medium);
            Assert.Equal("Apple", Best(tv, FactFields.Vendor)!.Value);
            Assert.Equal("media", Best(tv, FactFields.DeviceType)!.Value);
            Assert.Equal("A8:5B:78:11:22:33", Best(tv, FactFields.Mac)!.Value);
            Assert.Equal("fe80::1", Best(tv, FactFields.Ipv6)!.Value);
            Assert.Contains(tv, f => f.Field == FactFields.Service && f.Value == "_airplay._tcp" && f.Confidence == Confidence.Low);
            Assert.Contains(tv, f => f.Field == FactFields.Name && f.Value == "Living Room" && f.Confidence == Confidence.Medium);
            Assert.All(tv, f => Assert.Equal("mDNS", f.Source));

            IReadOnlyList<Fact> mb = all["192.168.1.20"];
            Assert.Equal("Kims-MBP", Best(mb, FactFields.Name)!.Value);
            Assert.Equal("MacBook Pro (14-inch, 2021)", Best(mb, FactFields.Model)!.Value);
            Assert.Equal(("macOS", Confidence.High), (Best(mb, FactFields.Os)!.Value, Best(mb, FactFields.Os)!.Confidence));
            Assert.Equal("macOS 14", Best(mb, FactFields.OsVersion)!.Value);
            Assert.Equal("computer", Best(mb, FactFields.DeviceType)!.Value);
            Assert.Contains(mb, f => f.Field == FactFields.Service && f.Value == "_smb._tcp");
            Assert.Contains(mb, f => f.Field == FactFields.Service && f.Value == "_device-info._tcp");
            // _smb만 보고 Windows라고 추측하지 않는다(macOS가 이미 있음)
            Assert.DoesNotContain(mb, f => f.Field == FactFields.Os && f.Value == "Windows");
        }

        [Fact]
        public void Mdns_FactsFromResponses_WorkstationGivesMacAndLinux_SmbAloneHintsWindows()
        {
            DnsCodec.Response r = new DnsMessageBuilder()
                .Ptr("_workstation._tcp.local", "pc7 [aa:bb:cc:dd:ee:ff]._workstation._tcp.local")
                .Srv("pc7 [aa:bb:cc:dd:ee:ff]._workstation._tcp.local", 9, "pc7.local")
                .A("pc7.local", "10.0.0.7")
                .Ptr("_smb._tcp.local", "WINBOX._smb._tcp.local")
                .Srv("WINBOX._smb._tcp.local", 445, "winbox.local")
                .A("winbox.local", "10.0.0.8")
                .Parse();
            IReadOnlyDictionary<string, IReadOnlyList<Fact>> all = MdnsBrowser.FactsFromResponses(new[] { r });

            IReadOnlyList<Fact> pc7 = all["10.0.0.7"];
            Assert.Equal("AA:BB:CC:DD:EE:FF", Best(pc7, FactFields.Mac)!.Value);
            Assert.Equal(("Linux", Confidence.Low), (Best(pc7, FactFields.Os)!.Value, Best(pc7, FactFields.Os)!.Confidence));

            IReadOnlyList<Fact> win = all["10.0.0.8"];
            Assert.Equal("winbox", Best(win, FactFields.Name)!.Value);
            Assert.Equal(("Windows", Confidence.Low), (Best(win, FactFields.Os)!.Value, Best(win, FactFields.Os)!.Confidence));
        }

        [Fact]
        public void Mdns_FactsFromResponses_PrinterAndChromecastTxtKeys()
        {
            DnsCodec.Response r = new DnsMessageBuilder()
                .Ptr("_ipp._tcp.local", "Brother HL-L2350DW series._ipp._tcp.local")
                .Srv("Brother HL-L2350DW series._ipp._tcp.local", 631, "BRW0123.local")
                .Txt("Brother HL-L2350DW series._ipp._tcp.local", "txtvers=1", "ty=Brother HL-L2350DW series", "product=(Brother HL-L2350DW series)", "usb_MFG=Brother", "usb_MDL=HL-L2350DW series")
                .A("BRW0123.local", "10.0.0.31")
                .Ptr("_googlecast._tcp.local", "Chromecast-abcdef._googlecast._tcp.local")
                .Srv("Chromecast-abcdef._googlecast._tcp.local", 8009, "abcdef-1234.local")
                .Txt("Chromecast-abcdef._googlecast._tcp.local", "id=abcdef", "md=Chromecast Ultra", "fn=Bedroom TV")
                .A("abcdef-1234.local", "10.0.0.32")
                .Parse();
            IReadOnlyDictionary<string, IReadOnlyList<Fact>> all = MdnsBrowser.FactsFromResponses(new[] { r });

            IReadOnlyList<Fact> printer = all["10.0.0.31"];
            Assert.Equal(("Brother HL-L2350DW series", Confidence.High), (Best(printer, FactFields.Model)!.Value, Best(printer, FactFields.Model)!.Confidence));
            Assert.Equal(("Brother", Confidence.High), (Best(printer, FactFields.Vendor)!.Value, Best(printer, FactFields.Vendor)!.Confidence));
            Assert.Equal("printer", Best(printer, FactFields.DeviceType)!.Value);

            IReadOnlyList<Fact> cast = all["10.0.0.32"];
            Assert.Equal("Google", Best(cast, FactFields.Vendor)!.Value);
            Assert.Equal("Chromecast Ultra", Best(cast, FactFields.Model)!.Value);
            Assert.Equal("Bedroom TV", Best(cast, FactFields.Name)!.Value);   // fn(Medium)보다 SRV 호스트(High)… 아래 확인
            Assert.Equal("media", Best(cast, FactFields.DeviceType)!.Value);
        }

        [Fact]
        public void Mdns_FactsFromResponses_InstanceWithoutAddressIsIgnored_AndEmptyIsEmpty()
        {
            DnsCodec.Response r = new DnsMessageBuilder()
                .Ptr("_http._tcp.local", "Nowhere._http._tcp.local")
                .Srv("Nowhere._http._tcp.local", 80, "nowhere.local")
                .Parse();
            Assert.Empty(MdnsBrowser.FactsFromResponses(new[] { r }));
            Assert.Empty(MdnsBrowser.FactsFromResponses(Array.Empty<DnsCodec.Response>()));
        }

        [Fact]
        public void Mdns_FollowUpQuestions_AsksSrvTxtForInstancesAndAForTargets_Once()
        {
            var asked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            DnsCodec.Response ptrOnly = new DnsMessageBuilder().Ptr("_ssh._tcp.local", "box._ssh._tcp.local").Parse();
            List<(string, ushort)> q1 = MdnsBrowser.FollowUpQuestions(new[] { ptrOnly }, asked);
            Assert.Equal(new[] { ("box._ssh._tcp.local", DnsCodec.TypeSrv), ("box._ssh._tcp.local", DnsCodec.TypeTxt) }, q1);
            Assert.Empty(MdnsBrowser.FollowUpQuestions(new[] { ptrOnly }, asked));   // 다시 묻지 않음

            DnsCodec.Response srv = new DnsMessageBuilder().Srv("box._ssh._tcp.local", 22, "box.local").Parse();
            List<(string, ushort)> q2 = MdnsBrowser.FollowUpQuestions(new[] { ptrOnly, srv }, asked);
            Assert.Equal(new[] { ("box.local", DnsCodec.TypeA), ("box.local", DnsCodec.TypeAaaa) }, q2);
        }

        [Fact]
        public void Mdns_BuildQuery_EncodesMultipleQuestionsWithQuBit()
        {
            byte[] q = MdnsBrowser.BuildQuery(new[] { ("_services._dns-sd._udp.local", DnsCodec.TypePtr), ("host.local", DnsCodec.TypeA) }, unicastResponse: true);
            Assert.Equal(0, q[0] | q[1]);              // ID 0
            Assert.Equal(2, (q[4] << 8) | q[5]);       // QDCOUNT
            // 첫 질문: 9"_services"7"_dns-sd"4"_udp"5"local"0 TYPE CLASS
            int p = 12;
            foreach (string label in new[] { "_services", "_dns-sd", "_udp", "local" })
            {
                Assert.Equal(label.Length, q[p]);
                Assert.Equal(label, Encoding.ASCII.GetString(q, p + 1, label.Length));
                p += 1 + label.Length;
            }
            Assert.Equal(0, q[p++]);
            Assert.Equal(DnsCodec.TypePtr, (q[p] << 8) | q[p + 1]);
            Assert.Equal(DnsCodec.ClassInUnicast, (q[p + 2] << 8) | q[p + 3]);
            // 멀티캐스트 응답 모드에서는 평범한 IN 클래스
            byte[] q2 = MdnsBrowser.BuildQuery(new[] { ("a.local", DnsCodec.TypeA) }, unicastResponse: false);
            Assert.Equal(DnsCodec.ClassIn, (q2[^2] << 8) | q2[^1]);
            // 질의도 DnsCodec 파서를 통과한다(질문 섹션을 건너뛴다)
            Assert.True(DnsCodec.TryParseResponse(q, out DnsCodec.Response parsed));
            Assert.False(parsed.IsResponse);
        }

        [Theory]
        [InlineData("My Printer._ipp._tcp.local", true, "My Printer", "_ipp._tcp.local")]
        [InlineData("a.b._airplay._tcp.local.", true, "a.b", "_airplay._tcp.local")]
        [InlineData("x._sleep-proxy._udp.local", true, "x", "_sleep-proxy._udp.local")]
        [InlineData("_ipp._tcp.local", false, "", "")]
        [InlineData("host.local", false, "", "")]
        public void Mdns_TrySplitInstance_SeparatesLabelAndServiceType(string full, bool ok, string label, string type)
        {
            Assert.Equal(ok, MdnsBrowser.TrySplitInstance(full, out string l, out string t));
            Assert.Equal(label, l);
            Assert.Equal(type, t);
        }

        [Theory]
        [InlineData("aabbccddeeff", "AA:BB:CC:DD:EE:FF")]
        [InlineData("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF")]
        [InlineData("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF")]
        [InlineData("aabbcc", null)]
        [InlineData("", null)]
        public void Mdns_NormalizeMac(string raw, string? expected) => Assert.Equal(expected, MdnsBrowser.NormalizeMac(raw));

        // ---------- Apple 모델 표 ----------

        [Theory]
        [InlineData("MacBookPro18,3", "MacBook Pro (14-inch, 2021)", "computer")]
        [InlineData("iPhone15,2", "iPhone 14 Pro", "phone")]
        [InlineData("iPad13,16", "iPad Air (5th gen)", "tablet")]
        [InlineData("J305AP", "Apple TV 4K (2nd gen)", "media")]
        [InlineData("J313AP", "Apple TV", "media")]                 // 표에 없는 J…AP 보드 → 일반 Apple TV
        [InlineData("MacBookPro99,9", "Apple MacBook Pro", "computer")]
        [InlineData("MacBookAir99,1", "Apple MacBook Air", "computer")]
        [InlineData("iMac99,1", "Apple iMac", "computer")]
        [InlineData("Macmini99,1", "Apple Mac mini", "computer")]
        [InlineData("iPhone99,1", "Apple iPhone", "phone")]
        [InlineData("iPad99,1", "Apple iPad", "tablet")]
        [InlineData("AppleTV99,1", "Apple TV", "media")]
        [InlineData("Watch7,1", "Apple Watch", "wearable")]
        [InlineData("macbookpro18,3", "MacBook Pro (14-inch, 2021)", "computer")]   // 대소문자 무시
        public void AppleModels_TryDescribe_MapsKnownAndFallsBackByFamily(string id, string name, string type)
        {
            Assert.True(AppleModels.TryDescribe(id, out AppleModels.Product p));
            Assert.Equal(name, p.Name);
            Assert.Equal(type, p.DeviceType);
        }

        [Theory]
        [InlineData("RT-AX88U")]
        [InlineData("Chromecast")]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("Galaxy S23")]
        public void AppleModels_TryDescribe_RejectsNonApple(string? id)
        {
            Assert.False(AppleModels.TryDescribe(id, out _));
        }

        [Theory]
        [InlineData("20", "11")]
        [InlineData("21", "12")]
        [InlineData("22", "13")]
        [InlineData("23", "14")]
        [InlineData("24", "15")]
        [InlineData("25", "26")]
        [InlineData("19", "10.15")]
        [InlineData("26", "27")]
        [InlineData("x", null)]
        [InlineData("", null)]
        [InlineData("5", null)]
        public void AppleModels_MapOsxVers(string osxvers, string? expected) => Assert.Equal(expected, AppleModels.MapOsxVers(osxvers));

        // ---------- UDP 프로브: 포트 게이트 ----------

        [Fact]
        public void UdpServiceProbes_PortListAndGate()
        {
            Assert.Equal(new[] { 53, 123, 1900, 69, 5060 }, UdpServiceProbes.UdpPorts);
            Assert.Equal(5, UdpServiceProbes.CreateAll().Count);
            Assert.True(UdpServiceProbes.ShouldRun(new[] { 22, 123 }, 123));
            Assert.True(UdpServiceProbes.ShouldRun(new[] { -1 }, 123));
            Assert.False(UdpServiceProbes.ShouldRun(new[] { 22, 80 }, 123));
            Assert.False(UdpServiceProbes.ShouldRun(Array.Empty<int>(), 123));
        }

        [Fact]
        public async Task UdpProbes_SkipWhenPortNotOpen_WithoutTouchingNetwork()
        {
            int[] none = { 22, 80 };
            foreach (IFactProbe p in UdpServiceProbes.CreateAll())
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                Assert.Empty(await p.ProbeAsync("127.0.0.1", none, 5000, CancellationToken.None));
                Assert.True(sw.ElapsedMilliseconds < 1000, $"{p.Name} should return immediately");
            }
            Assert.Empty(await new NtpProbe().ProbeAsync("not-an-ip", new[] { -1 }, 200, CancellationToken.None));
        }

        // ---------- NTP: 루프백 응답기 ----------

        private static byte[] BuildNtpServerReply(byte[] request, int stratum, byte[] refId)
        {
            var r = new byte[48];
            r[0] = 0x24;             // LI=0, VN=4, Mode=4(server)
            r[1] = (byte)stratum;
            r[2] = 6; r[3] = 0xEC;   // poll, precision
            Array.Copy(refId, 0, r, 12, 4);
            Array.Copy(request, 40, r, 24, 8);   // originate = 클라이언트 전송 타임스탬프
            uint now = (uint)(DateTime.UtcNow - new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            for (int off = 16; off <= 40; off += 8)
            {
                if (off == 24) continue;
                r[off] = (byte)(now >> 24); r[off + 1] = (byte)(now >> 16); r[off + 2] = (byte)(now >> 8); r[off + 3] = (byte)now;
            }
            return r;
        }

        [Fact]
        public async Task NtpProbe_Loopback_ReturnsServiceAndStratum()
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var stop = new CancellationTokenSource();
            Task responder = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult req;
                    try { req = await server.ReceiveAsync(stop.Token); } catch { return; }
                    if (req.Buffer.Length != 48 || (req.Buffer[0] & 0x07) != 3) continue;   // mode 3만 받는다
                    await server.SendAsync(BuildNtpServerReply(req.Buffer, 2, new byte[] { 10, 0, 0, 1 }), req.RemoteEndPoint, stop.Token);
                }
            });
            try
            {
                IReadOnlyList<Fact> facts = await new NtpProbe(port).ProbeAsync("127.0.0.1", new[] { 123 }, 3000, CancellationToken.None);
                Assert.NotEmpty(facts);
                Assert.Equal("NTP server (v4, stratum 2)", Best(facts, FactFields.Service)!.Value);
                Assert.Equal("NTP: stratum 2, ref 10.0.0.1", Best(facts, FactFields.Description)!.Value);
                Assert.All(facts, f => Assert.Equal("UDP", f.Source));
            }
            finally
            {
                stop.Cancel();
                server.Close();
                await responder;
            }
        }

        [Fact]
        public void NtpProbe_FactsFromReply_Stratum1UsesAsciiRefId_AndRejectsClientMode()
        {
            byte[] reply = BuildNtpServerReply(new byte[48], 1, Encoding.ASCII.GetBytes("GPS\0"));
            IReadOnlyList<Fact> facts = NtpProbe.FactsFromReply("1.2.3.4", reply);
            Assert.Equal("NTP: stratum 1, ref GPS", Best(facts, FactFields.Description)!.Value);

            byte[] clientMode = NtpProbe.BuildRequest();
            Assert.Empty(NtpProbe.FactsFromReply("1.2.3.4", clientMode));
            Assert.Empty(NtpProbe.FactsFromReply("1.2.3.4", new byte[10]));
        }

        // ---------- DNS: 루프백 응답기 ----------

        [Fact]
        public async Task DnsProbe_Loopback_ReturnsVersionBindAndRecursionHint()
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var stop = new CancellationTokenSource();
            Task responder = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult req;
                    try { req = await server.ReceiveAsync(stop.Token); } catch { return; }
                    if (!DnsCodec.TryParseResponse(req.Buffer, out DnsCodec.Response q) || q.IsResponse) continue;
                    bool isVersion = Encoding.ASCII.GetString(req.Buffer).Contains("version", StringComparison.OrdinalIgnoreCase);
                    // flags 0x8180: 응답, RD, RA
                    DnsMessageBuilder b = isVersion
                        ? new DnsMessageBuilder(q.Id, 0x8180).Txt("version.bind", "dnsmasq-2.90")
                        : new DnsMessageBuilder(q.Id, 0x8180).A("example.com", "93.184.216.34");
                    await server.SendAsync(b.Build(), req.RemoteEndPoint, stop.Token);
                }
            });
            try
            {
                IReadOnlyList<Fact> facts = await new DnsProbe(port).ProbeAsync("127.0.0.1", new[] { -1 }, 3000, CancellationToken.None);
                Assert.NotEmpty(facts);
                Assert.Equal("DNS server (dnsmasq-2.90)", Best(facts, FactFields.Service)!.Value);
                Assert.Equal("DNS: recursion available", Best(facts, FactFields.Description)!.Value);
                Assert.Equal(("Linux", Confidence.Low), (Best(facts, FactFields.Os)!.Value, Best(facts, FactFields.Os)!.Confidence));
            }
            finally
            {
                stop.Cancel();
                server.Close();
                await responder;
            }
        }

        [Fact]
        public void DnsProbe_FactsFromReplies_AnswerWithoutVersionStillCountsAsDnsServer()
        {
            byte[] refused = new DnsMessageBuilder(7, 0x8005).Build();   // 응답, RCODE=REFUSED
            IReadOnlyList<Fact> facts = DnsProbe.FactsFromReplies("1.1.1.1", null, refused);
            Assert.Equal("DNS server", Best(facts, FactFields.Service)!.Value);
            Assert.Equal("DNS: query refused", Best(facts, FactFields.Description)!.Value);
            Assert.Empty(DnsProbe.FactsFromReplies("1.1.1.1", null, null));
        }

        // ---------- TFTP / SIP 파싱 ----------

        [Fact]
        public void TftpProbe_FactsFromReply_ErrorAndDataBothMeanServer()
        {
            byte[] error = { 0, 5, 0, 1, (byte)'F', (byte)'i', (byte)'l', (byte)'e', (byte)' ', (byte)'n', (byte)'o', (byte)'t', (byte)' ', (byte)'f', (byte)'o', (byte)'u', (byte)'n', (byte)'d', 0 };
            IReadOnlyList<Fact> facts = TftpProbe.FactsFromReply("10.0.0.5", error);
            Assert.Equal(("TFTP server", Confidence.Low), (Best(facts, FactFields.Service)!.Value, Best(facts, FactFields.Service)!.Confidence));
            Assert.Contains("error 1 File not found", Best(facts, FactFields.Description)!.Value);
            Assert.Contains("exposure", Best(facts, FactFields.Description)!.Value);

            byte[] data = { 0, 3, 0, 1, 0xAA, 0xBB };
            Assert.Contains("served data", Best(TftpProbe.FactsFromReply("10.0.0.5", data), FactFields.Description)!.Value);
            Assert.Empty(TftpProbe.FactsFromReply("10.0.0.5", new byte[] { 0, 1, 0, 0 }));   // RRQ 에코는 서버가 아님

            byte[] rrq = TftpProbe.BuildReadRequest("x.bin");
            Assert.Equal(new byte[] { 0, 1 }, rrq.Take(2).ToArray());
            Assert.EndsWith("octet\0", Encoding.ASCII.GetString(rrq));
        }

        [Fact]
        public void SipProbe_FactsFromReply_UsesUserAgentOrServer()
        {
            IReadOnlyList<Fact> f1 = SipProbe.FactsFromReply("10.0.0.6", "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.2;branch=z9hG4bKabc\r\nUser-Agent: Asterisk PBX 18.9.0\r\nContent-Length: 0\r\n\r\n");
            Assert.Equal("SIP: Asterisk PBX 18.9.0", Best(f1, FactFields.Service)!.Value);
            Assert.Equal("voip", Best(f1, FactFields.DeviceType)!.Value);

            IReadOnlyList<Fact> f2 = SipProbe.FactsFromReply("10.0.0.6", "SIP/2.0 404 Not Found\r\nServer: Grandstream GXP1625\r\n\r\n");
            Assert.Equal("SIP: Grandstream GXP1625", Best(f2, FactFields.Service)!.Value);

            IReadOnlyList<Fact> f3 = SipProbe.FactsFromReply("10.0.0.6", "SIP/2.0 486 Busy Here\r\n\r\n");
            Assert.Equal("SIP (486 Busy Here)", Best(f3, FactFields.Service)!.Value);

            Assert.Empty(SipProbe.FactsFromReply("10.0.0.6", "HTTP/1.1 200 OK\r\n\r\n"));
            string options = Encoding.ASCII.GetString(SipProbe.BuildOptions("10.0.0.6", "10.0.0.2"));
            Assert.StartsWith("OPTIONS sip:10.0.0.6 SIP/2.0\r\n", options);
            Assert.Contains("CSeq: 1 OPTIONS", options);
            Assert.EndsWith("Content-Length: 0\r\n\r\n", options);
        }

        // ---------- 응답 없음 → 빈 목록 ----------

        [Fact]
        public async Task UdpProbes_SilentPort_ReturnEmptyWithinTimeout()
        {
            // 바인딩만 하고 답하지 않는 소켓
            using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;
            int[] any = { -1 };
            var probes = new IFactProbe[] { new NtpProbe(port), new DnsProbe(port), new TftpProbe(port), new SipProbe(port), new SsdpUnicastProbe(port, fetchDescription: false) };
            foreach (IFactProbe p in probes)
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                Assert.Empty(await p.ProbeAsync("127.0.0.1", any, 300, CancellationToken.None));
                Assert.True(sw.ElapsedMilliseconds < 2500, $"{p.Name} took {sw.ElapsedMilliseconds} ms");
            }
        }

        [Fact]
        public async Task SsdpUnicastProbe_Loopback_ParsesHeadersWithUdpSource()
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var stop = new CancellationTokenSource();
            Task responder = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult req;
                    try { req = await server.ReceiveAsync(stop.Token); } catch { return; }
                    if (!Encoding.ASCII.GetString(req.Buffer).StartsWith("M-SEARCH", StringComparison.Ordinal)) continue;
                    await server.SendAsync(Encoding.ASCII.GetBytes(SampleSsdp), req.RemoteEndPoint, stop.Token);
                }
            });
            try
            {
                IReadOnlyList<Fact> facts = await new SsdpUnicastProbe(port, fetchDescription: false).ProbeAsync("127.0.0.1", new[] { 1900 }, 3000, CancellationToken.None);
                Assert.NotEmpty(facts);
                Assert.Equal("router", Best(facts, FactFields.DeviceType)!.Value);
                Assert.Equal("Linux", Best(facts, FactFields.Os)!.Value);
                Assert.All(facts, f => Assert.Equal("UDP", f.Source));
            }
            finally
            {
                stop.Cancel();
                server.Close();
                await responder;
            }
        }

        // ---------- 멀티캐스트 발견: 실제 네트워크로는 "던지지 않고 돌아온다"만 확인 ----------

        [Fact]
        public async Task MulticastDiscoveries_ShortTimeout_ReturnWithoutThrowing()
        {
            var ssdp = new SsdpDiscovery();
            var mdns = new MdnsBrowser();
            Assert.Equal("SSDP", ssdp.Name);
            Assert.Equal("mDNS", mdns.Name);

            IReadOnlyDictionary<string, IReadOnlyList<Fact>> a = await ssdp.DiscoverAsync(300, CancellationToken.None);
            IReadOnlyDictionary<string, IReadOnlyList<Fact>> b = await mdns.DiscoverAsync(300, CancellationToken.None);
            Assert.NotNull(a);
            Assert.NotNull(b);
            Assert.All(a.Keys, k => Assert.True(IPAddress.TryParse(k, out _)));
            Assert.All(b.Keys, k => Assert.True(IPAddress.TryParse(k, out _)));

            // 이미 취소된 토큰 / 0 타임아웃 → 즉시 빈 결과
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            Assert.Empty(await ssdp.DiscoverAsync(5000, cts.Token));
            Assert.Empty(await mdns.DiscoverAsync(5000, cts.Token));
            Assert.Empty(await ssdp.DiscoverAsync(0, CancellationToken.None));
            Assert.Empty(await mdns.DiscoverAsync(0, CancellationToken.None));
        }

        [Fact]
        public void MulticastSocketSet_OpensAtLeastOneSenderAndDisposesCleanly()
        {
            using var set = MulticastSocketSet.Open(MdnsBrowser.MulticastGroup, MdnsBrowser.Port, 255, listenOnGroupPort: true);
            Assert.True(set.SenderCount >= 1);
            Assert.NotNull(MulticastSocketSet.LocalIPv4Addresses());
        }
    }
}
