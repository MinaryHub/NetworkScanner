using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Discovery;

namespace NetworkScanner.Tests
{
    public class IdentityProbeTests
    {
        // ---------- 패킷 조립 도우미 ----------

        // byte[] / byte / int(0~255) / string(ASCII)을 순서대로 이어 붙인다.
        private static byte[] Cat(params object[] parts)
        {
            var buf = new List<byte>();
            foreach (object p in parts)
            {
                switch (p)
                {
                    case byte[] b: buf.AddRange(b); break;
                    case byte b: buf.Add(b); break;
                    case int i: buf.Add(checked((byte)i)); break;
                    case string s: buf.AddRange(Encoding.ASCII.GetBytes(s)); break;
                    default: throw new ArgumentException(p?.GetType().Name);
                }
            }
            return buf.ToArray();
        }

        private static byte[] Hex(string hex)
            => Convert.FromHexString(hex.Replace(" ", "").Replace("\n", "").Replace("\r", ""));

        private static byte[] U16(int v) => new[] { (byte)(v >> 8), (byte)v };

        // ---------- SNMP ----------

        [Fact]
        public void Snmp_BuildGetRequest_ProducesWellFormedBer()
        {
            string[] oids = { SnmpProbe.OidSysDescr, SnmpProbe.OidSysObjectId, SnmpProbe.OidSysName, SnmpProbe.OidSysLocation };
            byte[] req = SnmpCodec.BuildGetRequest("public", 12345, oids);

            Assert.Equal(SnmpCodec.TagSequence, req[0]);
            Assert.Equal(req.Length - 2, req[1]);   // 짧은 길이 형식, 바깥 SEQUENCE가 전체를 덮는다

            Assert.True(SnmpCodec.TryParseMessage(req, out var msg));
            Assert.Equal(SnmpCodec.VersionV2c, msg.Version);
            Assert.Equal("public", msg.Community);
            Assert.Equal(SnmpCodec.PduGetRequest, msg.PduType);
            Assert.Equal(12345, msg.RequestId);
            Assert.Equal(0, msg.ErrorStatus);
            Assert.Equal(oids, msg.VarBinds.Select(v => v.Oid).ToArray());
            Assert.All(msg.VarBinds, v => Assert.Equal(SnmpCodec.TagNull, v.Tag));
        }

        [Fact]
        public void Snmp_EncodeInteger_UsesMinimalTwosComplement()
        {
            Assert.Equal(Hex("020100"), SnmpCodec.EncodeInteger(0));
            Assert.Equal(Hex("02017f"), SnmpCodec.EncodeInteger(127));
            Assert.Equal(Hex("02020080"), SnmpCodec.EncodeInteger(128));   // 양수 128은 선행 0x00이 필요
            Assert.Equal(Hex("0201ff"), SnmpCodec.EncodeInteger(-1));
            Assert.Equal(Hex("06082b060102010101 00"), SnmpCodec.EncodeOid("1.3.6.1.2.1.1.1.0"));
            Assert.Equal(Hex("060a2b06010401bf08 03020a"), SnmpCodec.EncodeOid("1.3.6.1.4.1.8072.3.2.10"));
        }

        // 캡처 형태의 GetResponse: sysDescr "Linux host 5.15", sysObjectID net-snmp, sysName "nas01", sysLocation noSuchObject
        private static readonly byte[] LinuxSnmpResponse = Hex(@"
            30 6e 02 01 01 04 06 70 75 62 6c 69 63 a2 61 02 01 2a 02 01 00 02 01 00 30 56
            30 1b 06 08 2b 06 01 02 01 01 01 00 04 0f 4c 69 6e 75 78 20 68 6f 73 74 20 35 2e 31 35
            30 16 06 08 2b 06 01 02 01 01 02 00 06 0a 2b 06 01 04 01 bf 08 03 02 0a
            30 11 06 08 2b 06 01 02 01 01 05 00 04 05 6e 61 73 30 31
            30 0c 06 08 2b 06 01 02 01 01 06 00 80 00");

        [Fact]
        public void Snmp_ParseResponse_LinuxNetSnmp_MapsOsAndVendor()
        {
            Assert.True(SnmpCodec.TryParseResponse(LinuxSnmpResponse, out int requestId, out var values));
            Assert.Equal(42, requestId);
            Assert.Equal("Linux host 5.15", values[SnmpProbe.OidSysDescr]);
            Assert.Equal("1.3.6.1.4.1.8072.3.2.10", values[SnmpProbe.OidSysObjectId]);
            Assert.Equal("nas01", values[SnmpProbe.OidSysName]);
            Assert.False(values.ContainsKey(SnmpProbe.OidSysLocation));   // noSuchObject는 값 없음

            HostIdentity? id = SnmpProbe.FromValues(values);
            Assert.NotNull(id);
            Assert.Equal(HostIdentity.SourceSnmp, id!.Source);
            Assert.Equal("nas01", id.Name);
            Assert.Equal("Linux host 5.15", id.Description);
            Assert.Equal("Linux", id.OsHint);
            Assert.Equal("net-snmp", id.Attributes["snmp.vendor"]);
            Assert.Equal("nas01", id.Attributes[HostIdentity.AttrSnmpSysName]);
        }

        [Fact]
        public void Snmp_ParseResponse_ErrorStatus_ReturnsFalse()
        {
            // 올바른 응답에서 error-status 바이트(오프셋 20)만 noSuchName(2)으로 바꾼다.
            byte[] bad = (byte[])LinuxSnmpResponse.Clone();
            Assert.Equal(0x00, bad[20]);
            bad[20] = 0x02;
            Assert.False(SnmpCodec.TryParseResponse(bad, out int requestId, out var values));
            Assert.Equal(42, requestId);
            Assert.Empty(values);

            // 잘린 패킷/쓰레기는 예외 없이 false
            Assert.False(SnmpCodec.TryParseResponse(LinuxSnmpResponse.Take(30).ToArray(), out _, out _));
            Assert.False(SnmpCodec.TryParseResponse(new byte[] { 1, 2, 3 }, out _, out _));
            // GetRequest는 응답으로 받지 않는다
            Assert.False(SnmpCodec.TryParseResponse(SnmpCodec.BuildGetRequest("public", 1, new[] { SnmpProbe.OidSysDescr }), out _, out _));
        }

        [Fact]
        public void Snmp_SysObjectId_EnterpriseAndKeywords_MapToHints()
        {
            Assert.Equal("Cisco", SnmpProbe.VendorFromObjectId("1.3.6.1.4.1.9.1.1208"));
            Assert.Equal("Brother", SnmpProbe.VendorFromObjectId(".1.3.6.1.4.1.2435.2.3.9.1"));
            Assert.Null(SnmpProbe.VendorFromObjectId("1.3.6.1.4.1.99999.1"));
            Assert.Null(SnmpProbe.VendorFromObjectId("1.3.6.1.2.1.1"));

            var cisco = SnmpProbe.FromValues(new Dictionary<string, string>
            {
                [SnmpProbe.OidSysDescr] = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE",
                [SnmpProbe.OidSysObjectId] = "1.3.6.1.4.1.9.1.716",
            })!;
            Assert.Equal("Cisco IOS", cisco.OsHint);
            Assert.Equal("network device", cisco.DeviceHint);
            Assert.Null(cisco.Name);   // sysName 없음

            var printer = SnmpProbe.FromValues(new Dictionary<string, string>
            {
                [SnmpProbe.OidSysDescr] = "Brother NC-8300w, Firmware Ver.1.17",
                [SnmpProbe.OidSysObjectId] = "1.3.6.1.4.1.2435.2.3.9.1",
                [SnmpProbe.OidSysName] = "BRW001122",
            })!;
            Assert.Equal("printer", printer.DeviceHint);
            Assert.Equal("BRW001122", printer.Name);

            var mikrotik = SnmpProbe.FromValues(new Dictionary<string, string>
            {
                [SnmpProbe.OidSysDescr] = "RouterOS RB750Gr3",
                [SnmpProbe.OidSysObjectId] = "1.3.6.1.4.1.14988.1",
            })!;
            Assert.Equal("RouterOS", mikrotik.OsHint);
            Assert.Equal("router", mikrotik.DeviceHint);

            // sysDescr 없는 응답은 실패
            Assert.Null(SnmpProbe.FromValues(new Dictionary<string, string> { [SnmpProbe.OidSysName] = "x" }));
        }

        // ---------- DNS / mDNS ----------

        [Fact]
        public void Dns_BuildQuery_EncodesReverseNameWithUnicastBit()
        {
            string reverse = DnsCodec.ReverseName(IPAddress.Parse("10.2.3.4"));
            Assert.Equal("4.3.2.10.in-addr.arpa", reverse);

            byte[] q = DnsCodec.BuildQuery(0x1234, reverse, DnsCodec.TypePtr, DnsCodec.ClassInUnicast);
            byte[] expected = Cat(
                U16(0x1234), U16(0), U16(1), U16(0), U16(0), U16(0),
                1, "4", 1, "3", 1, "2", 2, "10", 7, "in-addr", 4, "arpa", 0,
                U16(12), U16(0x8001));
            Assert.Equal(expected, q);
        }

        // 10.2.3.4 역방향 응답 + Additional(A, TXT). 이름 압축 포인터를 섞어 둔다.
        private static byte[] BuildMdnsResponse(ushort id) => Cat(
            U16(id), U16(0x8400), U16(1), U16(1), U16(0), U16(2),
            // question (오프셋 12)
            1, "4", 1, "3", 1, "2", 2, "10", 7, "in-addr", 4, "arpa", 0, U16(12), U16(1),
            // answer (오프셋 39): name → 질문 이름 포인터, PTR printer.local (rdata 오프셋 51, "local" 오프셋 59)
            0xC0, 0x0C, U16(12), U16(1), U16(0), U16(120), U16(15), 7, "printer", 5, "local", 0,
            // additional A: name → 포인터 51 (printer.local)
            0xC0, 51, U16(1), U16(1), U16(0), U16(120), U16(4), 10, 2, 3, 4,
            // additional TXT: "other" + 포인터 59 (local), 클래스에 cache-flush 비트
            5, "other", 0xC0, 59, U16(16), U16(0x8001), U16(0), U16(120), U16(12), 11, "model=Foo12");

        [Fact]
        public void Dns_ParseResponse_FollowsCompressionPointers()
        {
            Assert.True(DnsCodec.TryParseResponse(BuildMdnsResponse(0x2a), out var r));
            Assert.Equal(0x2a, r.Id);
            Assert.True(r.IsResponse);

            var ptr = Assert.Single(r.Answers);
            Assert.Equal("4.3.2.10.in-addr.arpa", ptr.Name);
            Assert.Equal(DnsCodec.TypePtr, ptr.Type);
            Assert.Equal("printer.local", ptr.Data);

            Assert.Equal(2, r.Additional.Count);
            Assert.Equal("printer.local", r.Additional[0].Name);
            Assert.Equal("10.2.3.4", r.Additional[0].Data);
            Assert.Equal("other.local", r.Additional[1].Name);
            Assert.Equal(DnsCodec.ClassIn, r.Additional[1].Class);   // cache-flush 비트 제거
            Assert.Equal("model=Foo12", r.Additional[1].Data);

            HostIdentity? id = MdnsProbe.FromResponse(r, "4.3.2.10.in-addr.arpa");
            Assert.NotNull(id);
            Assert.Equal("printer", id!.Name);
            Assert.Equal("mDNS: printer.local", id.Description);
            Assert.Equal("printer", id.Attributes[HostIdentity.AttrMdnsName]);
            Assert.Equal("10.2.3.4", id.Attributes["mdns.address"]);
            Assert.Equal("Foo12", id.Attributes["model"]);
            Assert.Equal("Foo12", id.DeviceHint);
        }

        [Fact]
        public void Dns_ParseResponse_RejectsPointerLoopsAndTruncation()
        {
            // 자기 자신을 가리키는 포인터 루프
            byte[] loop = Cat(U16(1), U16(0x8400), U16(0), U16(1), U16(0), U16(0), 0xC0, 12, U16(12), U16(1), U16(0), U16(0), U16(0));
            Assert.False(DnsCodec.TryParseResponse(loop, out _));
            // 헤더만 있는 잘린 패킷
            Assert.False(DnsCodec.TryParseResponse(new byte[5], out _));
            // 응답 레코드 수가 4라고 하면서 실제로는 3개(answer + additional 2)뿐인 경우
            byte[] good = BuildMdnsResponse(1);
            good[7] = 4;
            Assert.False(DnsCodec.TryParseResponse(good, out _));
        }

        // ---------- NetBIOS ----------

        [Fact]
        public void NetBios_BuildNodeStatusRequest_UsesWildcardName()
        {
            byte[] req = NetBiosCodec.BuildNodeStatusRequest(0xBEEF);
            Assert.Equal(50, req.Length);
            Assert.Equal(Cat(U16(0xBEEF), U16(0), U16(1), U16(0), U16(0), U16(0), 32, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0, U16(0x21), U16(1)), req);
        }

        private static byte[] BuildNbstatResponse(ushort id, byte[] mac, bool withServer = true)
        {
            var names = new List<byte[]>
            {
                Cat("DESKTOP-01     ", 0x00, U16(0x0400)),
                Cat("WORKGROUP      ", 0x00, U16(0x8400)),
            };
            if (withServer) names.Add(Cat("DESKTOP-01     ", 0x20, U16(0x0400)));
            byte[] nameBlock = names.SelectMany(n => n).ToArray();
            byte[] stats = Cat(mac, new byte[40]);
            int rdlen = 1 + nameBlock.Length + stats.Length;
            return Cat(
                U16(id), U16(0x8400), U16(0), U16(1), U16(0), U16(0),
                32, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0, U16(0x21), U16(1), U16(0), U16(0), U16(rdlen),
                names.Count, nameBlock, stats);
        }

        [Fact]
        public void NetBios_ParseNodeStatus_ExtractsNamesWorkgroupAndMac()
        {
            byte[] mac = { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
            Assert.True(NetBiosCodec.TryParseNodeStatusResponse(BuildNbstatResponse(7, mac), out ushort id, out var names, out string? macText));
            Assert.Equal(7, id);
            Assert.Equal("00:1A:2B:3C:4D:5E", macText);
            Assert.Equal(3, names.Count);
            Assert.Equal(("DESKTOP-01", (byte)0x00, false), (names[0].Name, names[0].Suffix, names[0].IsGroup));
            Assert.Equal(("WORKGROUP", (byte)0x00, true), (names[1].Name, names[1].Suffix, names[1].IsGroup));

            HostIdentity? ident = NetBiosProbe.FromNames(names, macText);
            Assert.NotNull(ident);
            Assert.Equal("DESKTOP-01", ident!.Name);
            Assert.Equal("WORKGROUP", ident.Attributes[HostIdentity.AttrNetBiosWorkgroup]);
            Assert.Equal("00:1A:2B:3C:4D:5E", ident.Attributes[HostIdentity.AttrNetBiosMac]);
            Assert.Equal("Windows", ident.OsHint);
            Assert.Equal("NetBIOS: DESKTOP-01 (WORKGROUP)", ident.Description);
        }

        [Fact]
        public void NetBios_ZeroMac_IsTreatedAsSamba()
        {
            Assert.True(NetBiosCodec.TryParseNodeStatusResponse(BuildNbstatResponse(1, new byte[6]), out _, out var names, out string? mac));
            HostIdentity ident = NetBiosProbe.FromNames(names, mac)!;
            Assert.Equal("Windows/SMB", ident.OsHint);
            Assert.False(ident.Attributes.ContainsKey(HostIdentity.AttrNetBiosMac));
        }

        [Fact]
        public void NetBios_ParseNodeStatus_RejectsNonResponseOrWrongType()
        {
            byte[] r = BuildNbstatResponse(1, new byte[6]);
            r[2] = 0x00;   // QR 비트 해제
            Assert.False(NetBiosCodec.TryParseNodeStatusResponse(r, out _, out _, out _));
            Assert.False(NetBiosCodec.TryParseNodeStatusResponse(new byte[3], out _, out _, out _));
        }

        // ---------- 병합 / 이름 선택 ----------

        private static HostIdentity Make(string source, string? name, string? desc, string? os, string? dev, params (string, string)[] attrs)
            => new(source, name, desc, os, dev, attrs.ToDictionary(a => a.Item1, a => a.Item2));

        [Fact]
        public void Merge_FollowsPriorityAndPrefersSnmpDescription()
        {
            var snmp = Make(HostIdentity.SourceSnmp, "nas01", "Linux host 5.15", "Linux", "nas",
                (HostIdentity.AttrSnmpSysName, "nas01"), ("shared", "snmp"));
            var mdns = Make(HostIdentity.SourceMdns, "nas01-mdns", "mDNS: nas01.local", null, null,
                (HostIdentity.AttrMdnsName, "nas01-mdns"), ("shared", "mdns"));
            var nb = Make(HostIdentity.SourceNetBios, "NAS01", "NetBIOS: NAS01 (HOME)", "Windows/SMB", null,
                (HostIdentity.AttrNetBiosName, "NAS01"), (HostIdentity.AttrNetBiosWorkgroup, "HOME"));

            // 입력 순서와 무관하게 우선순위(NetBIOS, mDNS, SNMP)로 정한다.
            HostIdentity merged = HostIdentityMerge.Merge(new[] { snmp, mdns, nb })!;
            Assert.Equal("NAS01", merged.Name);
            Assert.Equal("Linux host 5.15", merged.Description);
            Assert.Equal("Windows/SMB", merged.OsHint);
            Assert.Equal("nas", merged.DeviceHint);
            Assert.Equal("NetBIOS+mDNS+SNMP", merged.Source);
            Assert.Equal("mdns", merged.Attributes["shared"]);   // 합집합: 우선순위가 높은 쪽 값 유지
            Assert.Equal("HOME", merged.Attributes[HostIdentity.AttrNetBiosWorkgroup]);
            Assert.Equal("nas01", merged.Attributes[HostIdentity.AttrSnmpSysName]);

            // SNMP 없으면 우선순위상 첫 설명
            Assert.Equal("NetBIOS: NAS01 (HOME)", HostIdentityMerge.Merge(new[] { mdns, nb })!.Description);
            Assert.Null(HostIdentityMerge.Merge(Array.Empty<HostIdentity>()));
            Assert.Same(snmp, HostIdentityMerge.Merge(new[] { snmp }));
        }

        [Fact]
        public void ChooseName_PrefersRealDnsThenNetBiosMdnsSnmp()
        {
            var merged = Make("x", "fallback", null, null, null,
                (HostIdentity.AttrNetBiosName, "NB"), (HostIdentity.AttrMdnsName, "md"), (HostIdentity.AttrSnmpSysName, "sn"));

            Assert.Equal("host.example.com", HostIdentityMerge.ChooseName("host.example.com", merged));
            Assert.Equal("NB", HostIdentityMerge.ChooseName("192.168.0.10", merged));   // IP 문자열은 이름이 아니다
            Assert.Equal("NB", HostIdentityMerge.ChooseName(null, merged));
            Assert.Equal("md", HostIdentityMerge.ChooseName("", Make("x", null, null, null, null,
                (HostIdentity.AttrMdnsName, "md"), (HostIdentity.AttrSnmpSysName, "sn"))));
            Assert.Equal("sn", HostIdentityMerge.ChooseName(" ", Make("x", null, null, null, null, (HostIdentity.AttrSnmpSysName, "sn"))));
            Assert.Equal("fallback", HostIdentityMerge.ChooseName(null, Make("x", "fallback", null, null, null)));
            Assert.Null(HostIdentityMerge.ChooseName("10.0.0.1", null));
        }

        // ---------- Composite ----------

        private sealed class FakeProbe : IIdentityProbe
        {
            private readonly Func<CancellationToken, Task<HostIdentity?>> _run;
            public FakeProbe(string name, Func<CancellationToken, Task<HostIdentity?>> run) { Name = name; _run = run; }
            public string Name { get; }
            public Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct) => _run(ct);
        }

        [Fact]
        public async Task Composite_RunsConcurrently_OrdersByPriority_AndSwallowsFailures()
        {
            var snmp = Make(HostIdentity.SourceSnmp, "s", "Linux", "Linux", null, (HostIdentity.AttrSnmpSysName, "s"));
            var nb = Make(HostIdentity.SourceNetBios, "N", "NetBIOS: N", "Windows", null, (HostIdentity.AttrNetBiosName, "N"));
            var composite = new CompositeIdentityProbe(new IIdentityProbe[]
            {
                new FakeProbe("SNMP", async _ => { await Task.Delay(50); return snmp; }),
                new FakeProbe("boom", _ => throw new InvalidOperationException("probe bug")),
                new FakeProbe("none", _ => Task.FromResult<HostIdentity?>(null)),
                new FakeProbe("NetBIOS", async _ => { await Task.Delay(100); return nb; }),
            });

            var sw = Stopwatch.StartNew();
            IReadOnlyList<HostIdentity> all = await composite.ProbeAllAsync(IPAddress.Loopback, 1000, CancellationToken.None);
            sw.Stop();
            Assert.Equal(new[] { HostIdentity.SourceNetBios, HostIdentity.SourceSnmp }, all.Select(a => a.Source).ToArray());
            Assert.True(sw.ElapsedMilliseconds < 900, $"프로브가 순차 실행된 것 같음: {sw.ElapsedMilliseconds}ms");

            HostIdentity? merged = await composite.ProbeAsync(IPAddress.Loopback, 1000, CancellationToken.None);
            Assert.Equal("N", merged!.Name);
            Assert.Equal("Linux", merged.Description);
        }

        [Fact]
        public async Task Composite_WithCancelledToken_ReturnsNullWithoutThrowing()
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var composite = new CompositeIdentityProbe(new IIdentityProbe[]
            {
                new FakeProbe("a", ct => { ct.ThrowIfCancellationRequested(); return Task.FromResult<HostIdentity?>(null); }),
                new NetBiosProbe(), new MdnsProbe(), new SnmpProbe(),
            });
            Assert.Null(await composite.ProbeAsync(IPAddress.Loopback, 500, cts.Token));
            Assert.Equal(CompositeIdentityProbe.DefaultPriority, CompositeIdentityProbe.Create(true, true, true)!.Priority);
            Assert.Null(CompositeIdentityProbe.Create(false, false, false));
        }

        // ---------- 루프백 소켓 경로 ----------

        [Fact]
        public async Task SnmpProbe_Loopback_EndToEnd_ReturnsIdentity()
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var stop = new CancellationTokenSource();

            // 요청을 디코딩해 같은 request-id로 canned 응답을 돌려주는 초소형 SNMP 에이전트
            Task responder = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    UdpReceiveResult req;
                    try { req = await server.ReceiveAsync(stop.Token); }
                    catch { return; }
                    if (!SnmpCodec.TryParseMessage(req.Buffer, out var msg) || msg.Community != "s3cret") continue;
                    byte[] reply = SnmpCodec.BuildGetResponse("s3cret", msg.RequestId, new (string, byte, string?)[]
                    {
                        (SnmpProbe.OidSysDescr, SnmpCodec.TagOctetString, "Linux host 5.15"),
                        (SnmpProbe.OidSysObjectId, SnmpCodec.TagOid, "1.3.6.1.4.1.8072.3.2.10"),
                        (SnmpProbe.OidSysName, SnmpCodec.TagOctetString, "nas01"),
                        (SnmpProbe.OidSysLocation, SnmpCodec.TagNoSuchObject, null),
                    });
                    await server.SendAsync(reply, req.RemoteEndPoint, stop.Token);
                }
            });

            try
            {
                // community 불일치 → 응답 없음 → null
                Assert.Null(await new SnmpProbe("public", port).ProbeAsync(IPAddress.Loopback, 400, CancellationToken.None));

                HostIdentity? id = await new SnmpProbe("s3cret", port).ProbeAsync(IPAddress.Loopback, 3000, CancellationToken.None);
                Assert.NotNull(id);
                Assert.Equal("nas01", id!.Name);
                Assert.Equal("Linux", id.OsHint);
                Assert.Equal("Linux host 5.15", id.Attributes[HostIdentity.AttrSnmpSysDescr]);
            }
            finally
            {
                stop.Cancel();
                server.Close();
                await responder;
            }
        }

        [Fact]
        public async Task NetBiosProbe_Loopback_EndToEnd_ReturnsIdentity()
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var stop = new CancellationTokenSource();
            byte[] mac = { 0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03 };

            Task responder = Task.Run(async () =>
            {
                try
                {
                    UdpReceiveResult req = await server.ReceiveAsync(stop.Token);
                    ushort id = (ushort)((req.Buffer[0] << 8) | req.Buffer[1]);
                    Assert.Equal(0x21, req.Buffer[47]);   // QTYPE NBSTAT
                    await server.SendAsync(BuildNbstatResponse(id, mac), req.RemoteEndPoint, stop.Token);
                }
                catch (OperationCanceledException) { }
            });

            try
            {
                HostIdentity? id = await new NetBiosProbe(port).ProbeAsync(IPAddress.Loopback, 3000, CancellationToken.None);
                Assert.NotNull(id);
                Assert.Equal("DESKTOP-01", id!.Name);
                Assert.Equal("AA:BB:CC:01:02:03", id.Attributes[HostIdentity.AttrNetBiosMac]);
            }
            finally
            {
                stop.Cancel();
                server.Close();
                await responder;
            }
        }

        [Fact]
        public async Task Probes_AgainstClosedPort_ReturnNullWithinTimeout()
        {
            // 포트를 하나 잡았다가 바로 닫아 "닫힌" 포트 번호를 얻는다.
            int port;
            using (var tmp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
                port = ((IPEndPoint)tmp.Client.LocalEndPoint!).Port;

            var probes = new IIdentityProbe[] { new SnmpProbe("public", port), new MdnsProbe(port), new NetBiosProbe(port) };
            foreach (IIdentityProbe probe in probes)
            {
                var sw = Stopwatch.StartNew();
                HostIdentity? id = await probe.ProbeAsync(IPAddress.Loopback, 300, CancellationToken.None);
                sw.Stop();
                Assert.Null(id);
                Assert.True(sw.ElapsedMilliseconds < 2000, $"{probe.Name}: {sw.ElapsedMilliseconds}ms");
            }
        }
    }
}
