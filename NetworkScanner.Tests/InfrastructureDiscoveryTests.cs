using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Discovery;
using NetworkScanner.Discovery.Infrastructure;

namespace NetworkScanner.Tests
{
    public class InfrastructureDiscoveryTests
    {
        // ---------- 가짜 SNMP 에이전트: 정렬된 MIB 위에서 GET/GETNEXT/GETBULK를 흉내 낸다 ----------

        private sealed class FakeAgent
        {
            public readonly List<(string Oid, byte Tag, byte[] Raw)> Mib = new();
            public bool RejectBulk;   // GETBULK에 genErr(5)로 답한다(SNMPv1류)
            public bool DropBulk;     // GETBULK를 조용히 버린다
            public bool Silent;       // 아무 요청에도 답하지 않는다
            public Func<byte[], byte[]?>? Override; // 요청 가로채기(깨진 응답 등)
            public readonly List<byte> RequestTypes = new();
            public int MaxRepetitionsSeen = -1;

            public FakeAgent Int(string oid, long v) { Mib.Add((oid, SnmpBer.TagInteger, SnmpBer.IntegerContent(v))); return this; }
            public FakeAgent Str(string oid, string s) { Mib.Add((oid, SnmpBer.TagOctetString, Encoding.UTF8.GetBytes(s))); return this; }
            public FakeAgent Bytes(string oid, byte[] b) { Mib.Add((oid, SnmpBer.TagOctetString, b)); return this; }
            public FakeAgent Ip(string oid, string ip) { Mib.Add((oid, SnmpBer.TagIpAddress, IPAddress.Parse(ip).GetAddressBytes())); return this; }

            private List<(string Oid, byte Tag, byte[] Raw)> Sorted()
            {
                var copy = new List<(string, byte, byte[])>(Mib);
                copy.Sort((a, b) => OidUtil.Compare(a.Item1, b.Item1));
                return copy;
            }

            public Task<byte[]?> Handle(byte[] request)
            {
                if (Override != null) return Task.FromResult(Override(request));
                if (Silent || !SnmpBer.TryParse(request, out SnmpBer.Pdu pdu)) return Task.FromResult<byte[]?>(null);
                RequestTypes.Add(pdu.Type);
                var mib = Sorted();
                var vbs = new List<SnmpBer.VarBind>();

                switch (pdu.Type)
                {
                    case SnmpBer.PduGetRequest:
                        foreach (SnmpBer.VarBind vb in pdu.VarBinds)
                        {
                            int i = mib.FindIndex(r => OidUtil.Compare(r.Oid, vb.Oid) == 0);
                            vbs.Add(i < 0 ? new SnmpBer.VarBind(vb.Oid, SnmpBer.TagNoSuchObject, Array.Empty<byte>())
                                          : new SnmpBer.VarBind(mib[i].Oid, mib[i].Tag, mib[i].Raw));
                        }
                        break;
                    case SnmpBer.PduGetNext:
                        foreach (SnmpBer.VarBind vb in pdu.VarBinds) vbs.Add(Next(mib, vb.Oid));
                        break;
                    case SnmpBer.PduGetBulk:
                        if (DropBulk) return Task.FromResult<byte[]?>(null);
                        if (RejectBulk) return Task.FromResult<byte[]?>(SnmpBer.BuildResponse(pdu.Community, pdu.RequestId, 5, 1, pdu.VarBinds));
                        MaxRepetitionsSeen = pdu.ErrorIndex;
                        string cur = pdu.VarBinds[0].Oid;
                        for (int r = 0; r < pdu.ErrorIndex; r++)
                        {
                            SnmpBer.VarBind n = Next(mib, cur);
                            vbs.Add(n);
                            if (n.Tag == SnmpBer.TagEndOfMibView) break;
                            cur = n.Oid;
                        }
                        break;
                    default:
                        return Task.FromResult<byte[]?>(null);
                }
                return Task.FromResult<byte[]?>(SnmpBer.BuildResponse(pdu.Community, pdu.RequestId, 0, 0, vbs));
            }

            private static SnmpBer.VarBind Next(List<(string Oid, byte Tag, byte[] Raw)> mib, string oid)
            {
                foreach (var r in mib)
                    if (OidUtil.Compare(r.Oid, oid) > 0) return new SnmpBer.VarBind(r.Oid, r.Tag, r.Raw);
                return new SnmpBer.VarBind(oid, SnmpBer.TagEndOfMibView, Array.Empty<byte>());
            }
        }

        private static readonly IPAddress Agent = IPAddress.Parse("10.0.0.1");

        private static SnmpWalker WalkerFor(FakeAgent agent) => new(agent.Handle);

        // ---------- BER: GETBULK/GETNEXT 왕복 ----------

        [Fact]
        public void GetBulk_RoundTrip_ThroughDecoder()
        {
            byte[] req = SnmpBer.BuildGetBulk("public", 12345, "1.3.6.1.2.1.4.22.1.2", 0, 25);
            Assert.True(SnmpBer.TryParse(req, out SnmpBer.Pdu pdu));
            Assert.Equal(SnmpBer.PduGetBulk, pdu.Type);
            Assert.Equal(0xA5, pdu.Type);
            Assert.Equal(1, pdu.Version);
            Assert.Equal("public", pdu.Community);
            Assert.Equal(12345, pdu.RequestId);
            Assert.Equal(0, pdu.ErrorStatus);  // non-repeaters
            Assert.Equal(25, pdu.ErrorIndex);  // max-repetitions
            Assert.Single(pdu.VarBinds);
            Assert.Equal("1.3.6.1.2.1.4.22.1.2", pdu.VarBinds[0].Oid);
            Assert.Equal(SnmpBer.TagNull, pdu.VarBinds[0].Tag);
        }

        [Fact]
        public void GetNext_RoundTrip_ThroughDecoder()
        {
            byte[] req = SnmpBer.BuildGetNext("private", 7, "1.0.8802.1.1.2.1.4.1.1");
            Assert.True(SnmpBer.TryParse(req, out SnmpBer.Pdu pdu));
            Assert.Equal(0xA1, pdu.Type);
            Assert.Equal("private", pdu.Community);
            Assert.Equal(7, pdu.RequestId);
            Assert.Equal("1.0.8802.1.1.2.1.4.1.1", pdu.VarBinds[0].Oid);
        }

        [Fact]
        public void Response_RawValuesPreserved_AndTextFormatted()
        {
            var mac = new byte[] { 0x00, 0x23, 0xAA, 0x3A, 0x82, 0xBA };
            byte[] resp = SnmpBer.BuildResponse("public", 1, 0, 0, new[]
            {
                new SnmpBer.VarBind("1.3.6.1.2.1.1.5.0", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("core-sw")),
                new SnmpBer.VarBind("1.3.6.1.2.1.4.22.1.2.1.10.0.0.5", SnmpBer.TagOctetString, mac),
                new SnmpBer.VarBind("1.3.6.1.2.1.2.2.1.10.1", SnmpBer.TagCounter32, new byte[] { 0x00, 0xFF, 0xFF, 0xFF, 0xFF }),
                new SnmpBer.VarBind("1.3.6.1.2.1.1.2.0", SnmpBer.TagOid, SnmpBer.OidContent("1.3.6.1.4.1.9.1.1")),
                new SnmpBer.VarBind("1.3.6.1.2.1.4.20.1.1.10.0.0.1", SnmpBer.TagIpAddress, new byte[] { 10, 0, 0, 1 }),
                new SnmpBer.VarBind("1.3.6.1.2.1.2.2.1.8.1", SnmpBer.TagInteger, SnmpBer.IntegerContent(-2)),
                new SnmpBer.VarBind("1.3.6.1.2.1.31.1.1.1.6.1", SnmpBer.TagCounter64, new byte[] { 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0 }),
            });
            Assert.True(SnmpBer.TryParse(resp, out SnmpBer.Pdu pdu));
            Assert.Equal(SnmpBer.PduResponse, pdu.Type);
            Assert.Equal(7, pdu.VarBinds.Count);
            Assert.Equal("core-sw", SnmpBer.FormatText(pdu.VarBinds[0].Tag, pdu.VarBinds[0].Raw));
            Assert.Equal(mac, pdu.VarBinds[1].Raw);
            Assert.Equal("00-23-AA-3A-82-BA", SnmpBer.FormatText(pdu.VarBinds[1].Tag, pdu.VarBinds[1].Raw));
            Assert.Equal("4294967295", SnmpBer.FormatText(pdu.VarBinds[2].Tag, pdu.VarBinds[2].Raw));
            Assert.Equal("1.3.6.1.4.1.9.1.1", SnmpBer.FormatText(pdu.VarBinds[3].Tag, pdu.VarBinds[3].Raw));
            Assert.Equal("10.0.0.1", SnmpBer.FormatText(pdu.VarBinds[4].Tag, pdu.VarBinds[4].Raw));
            Assert.Equal("-2", SnmpBer.FormatText(pdu.VarBinds[5].Tag, pdu.VarBinds[5].Raw));
            Assert.Equal("9223372036854775808", SnmpBer.FormatText(pdu.VarBinds[6].Tag, pdu.VarBinds[6].Raw));
        }

        [Fact]
        public void TryParse_TruncatedOrGarbage_ReturnsFalseWithoutThrowing()
        {
            byte[] good = SnmpBer.BuildGetBulk("public", 1, "1.3.6.1.2.1", 0, 10);
            for (int cut = 0; cut < good.Length; cut++)
                Assert.False(SnmpBer.TryParse(good.Take(cut).ToArray(), out _));
            Assert.False(SnmpBer.TryParse(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, out _));
            Assert.False(SnmpBer.TryParse(null, out _));
        }

        // ---------- 걷기 종료 논리 ----------

        private static FakeAgent ArpAgent(int hosts = 3)
        {
            var a = new FakeAgent().Str("1.3.6.1.2.1.1.5.0", "gw");
            for (int i = 1; i <= hosts; i++)
                a.Bytes($"1.3.6.1.2.1.4.22.1.2.1.10.0.0.{i}", new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, (byte)i });
            a.Int("1.3.6.1.2.1.4.22.1.4.1.10.0.0.1", 3); // ipNetToMediaType — 부분트리 밖
            return a;
        }

        [Fact]
        public async Task Walk_StopsWhenOidLeavesSubtree_AndUsesBulk()
        {
            FakeAgent agent = ArpAgent();
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.2.1.4.22.1.2", 500, CancellationToken.None);
            Assert.Equal(3, rows.Count);
            Assert.All(rows, r => Assert.StartsWith("1.3.6.1.2.1.4.22.1.2.", r.Oid));
            Assert.Equal("00-11-22-33-44-01", rows[0].Text);
            Assert.Equal(SnmpBer.TagOctetString, rows[0].Type);
            Assert.Equal(6, rows[0].Raw.Length);
            Assert.All(agent.RequestTypes, t => Assert.Equal(SnmpBer.PduGetBulk, t));
            Assert.Single(agent.RequestTypes); // 25행 한 페이지에 다 들어온다
            Assert.Equal(25, agent.MaxRepetitionsSeen);
        }

        [Fact]
        public async Task Walk_StopsAtEndOfMibView()
        {
            var agent = new FakeAgent();
            for (int i = 1; i <= 30; i++) agent.Int($"1.3.6.1.4.1.99.1.{i}", i); // MIB의 끝까지 이어지는 부분트리
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.4.1.99", 500, CancellationToken.None);
            Assert.Equal(30, rows.Count);
            Assert.Equal("30", rows[29].Text);
            Assert.Equal(2, agent.RequestTypes.Count); // 25 + 5(+endOfMibView)
        }

        [Fact]
        public async Task Walk_BulkError_FallsBackToGetNext()
        {
            FakeAgent agent = ArpAgent();
            agent.RejectBulk = true;
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.2.1.4.22.1.2", 500, CancellationToken.None);
            Assert.Equal(3, rows.Count);
            Assert.Equal(SnmpBer.PduGetBulk, agent.RequestTypes[0]);
            Assert.All(agent.RequestTypes.Skip(1), t => Assert.Equal(SnmpBer.PduGetNext, t));
            Assert.Equal(1 + 4, agent.RequestTypes.Count); // bulk 1 + getnext 3행 + 부분트리 밖 1
        }

        [Fact]
        public async Task Walk_BulkSilentlyDropped_FallsBackToGetNext()
        {
            FakeAgent agent = ArpAgent();
            agent.DropBulk = true;
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.2.1.4.22.1.2", 500, CancellationToken.None);
            Assert.Equal(3, rows.Count);
            Assert.Contains(SnmpBer.PduGetNext, agent.RequestTypes);
        }

        [Fact]
        public async Task Walk_AgentRepeatsSameOid_StopsInsteadOfLooping()
        {
            var agent = new FakeAgent();
            agent.Override = req =>
            {
                SnmpBer.TryParse(req, out SnmpBer.Pdu pdu);
                // 항상 같은 행을 돌려주는 고장난 에이전트
                return SnmpBer.BuildResponse(pdu.Community, pdu.RequestId, 0, 0, new[]
                {
                    new SnmpBer.VarBind("1.3.6.1.4.1.99.1.1", SnmpBer.TagInteger, SnmpBer.IntegerContent(1)),
                    new SnmpBer.VarBind("1.3.6.1.4.1.99.1.1", SnmpBer.TagInteger, SnmpBer.IntegerContent(1)),
                });
            };
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.4.1.99", 500, CancellationToken.None);
            Assert.Single(rows);
        }

        [Fact]
        public async Task Walk_CapsAt5000Rows()
        {
            var agent = new FakeAgent();
            for (int i = 1; i <= 5200; i++) agent.Int($"1.3.6.1.4.1.99.1.{i}", i);
            var rows = await WalkerFor(agent).WalkAsync(Agent, "public", "1.3.6.1.4.1.99", 10000, CancellationToken.None); // 208페이지를 돌 시간
            Assert.Equal(SnmpWalker.MaxRows, rows.Count);
        }

        [Fact]
        public async Task Walk_GarbageMidWay_ReturnsRowsSoFar()
        {
            var agent = new FakeAgent();
            for (int i = 1; i <= 40; i++) agent.Int($"1.3.6.1.4.1.99.1.{i}", i);
            int calls = 0;
            Func<byte[], Task<byte[]?>> transport = async req =>
            {
                if (++calls >= 2) return new byte[] { 0x30, 0x02, 0xFF }; // 두 번째 페이지부터 깨진 응답
                return await agent.Handle(req);
            };
            var rows = await new SnmpWalker(transport).WalkAsync(Agent, "public", "1.3.6.1.4.1.99", 500, CancellationToken.None);
            Assert.Equal(25, rows.Count);
        }

        [Fact]
        public async Task Walk_NoResponseOrBadBase_ReturnsEmpty()
        {
            var silent = new SnmpWalker(_ => Task.FromResult<byte[]?>(null));
            Assert.Empty(await silent.WalkAsync(Agent, "public", "1.3.6.1.2.1", 100, CancellationToken.None));
            Assert.Empty(await WalkerFor(ArpAgent()).WalkAsync(Agent, "public", "not.an.oid", 100, CancellationToken.None));
            Assert.Empty(await WalkerFor(ArpAgent()).WalkAsync(Agent, "public", "1.3.6.1.2.1", 0, CancellationToken.None));
        }

        [Fact]
        public async Task Walk_IgnoresResponseWithWrongRequestId()
        {
            var agent = ArpAgent();
            Func<byte[], Task<byte[]?>> transport = async req =>
            {
                byte[]? r = await agent.Handle(req);
                if (r == null) return null;
                SnmpBer.TryParse(r, out SnmpBer.Pdu pdu);
                return SnmpBer.BuildResponse(pdu.Community, pdu.RequestId + 1, 0, 0, pdu.VarBinds); // 엉뚱한 요청 ID
            };
            Assert.Empty(await new SnmpWalker(transport).WalkAsync(Agent, "public", "1.3.6.1.2.1.4.22.1.2", 100, CancellationToken.None));
        }

        [Fact]
        public async Task Get_UsesSnmpCodec_AndReturnsValues()
        {
            FakeAgent agent = ArpAgent();
            var values = await WalkerFor(agent).GetAsync(Agent, "public", new[] { "1.3.6.1.2.1.1.5.0" }, 500, CancellationToken.None);
            Assert.NotNull(values);
            Assert.Equal("gw", values!["1.3.6.1.2.1.1.5.0"]);
            Assert.Equal(SnmpBer.PduGetRequest, agent.RequestTypes[0]);
            agent.Silent = true;
            Assert.Null(await WalkerFor(agent).GetAsync(Agent, "public", new[] { "1.3.6.1.2.1.1.5.0" }, 100, CancellationToken.None));
        }

        // ---------- 인덱스 해석 ----------

        [Fact]
        public void IpNetToPhysicalIndex_ParsesIpv4AndIpv6()
        {
            Assert.True(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.35.1.4.2.1.4.192.168.75.20", out IPAddress? ip4));
            Assert.Equal("192.168.75.20", ip4!.ToString());

            string v6Arcs = string.Join(".", IPAddress.Parse("fe80::1").GetAddressBytes());
            Assert.True(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.35.1.4.2.2.16." + v6Arcs, out IPAddress? ip6));
            Assert.Equal("fe80::1", ip6!.ToString());

            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.35.1.4.2.1.4.192.168", out _)); // 짧음
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.35.1.4.2.1.4.192.168.75.999", out _)); // 옥텟 범위
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.35.1.4.2.16.4.1.2.3.4", out _)); // 알 수 없는 addrType
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToPhysicalIndex("1.3.6.1.2.1.4.22.1.2.1.1.2.3.4", out _)); // 다른 테이블
        }

        [Fact]
        public void IpNetToMediaIndex_ParsesIfIndexAndIp()
        {
            Assert.True(SnmpInfrastructureDiscovery.TryParseIpNetToMediaIndex("1.3.6.1.2.1.4.22.1.2.3.10.20.30.40", out IPAddress? ip));
            Assert.Equal("10.20.30.40", ip!.ToString());
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToMediaIndex("1.3.6.1.2.1.4.22.1.2.3.10.20.30", out _));
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToMediaIndex("1.3.6.1.2.1.4.22.1.2.3.10.20.30.40.50", out _));
            Assert.False(SnmpInfrastructureDiscovery.TryParseIpNetToMediaIndex("1.3.6.1.2.1.4.22.1.2.3.10.20.30.256", out _));
        }

        [Fact]
        public void FdbIndex_ParsesMac_Dot1dAndDot1q()
        {
            Assert.Equal("00-1A-2B-3C-4D-5E", SnmpInfrastructureDiscovery.ParseFdbIndexMac("1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.94", SnmpInfrastructureDiscovery.OidDot1dTpFdbPort, false));
            Assert.Equal("00-1A-2B-3C-4D-5E", SnmpInfrastructureDiscovery.ParseFdbIndexMac("1.3.6.1.2.1.17.7.1.2.2.1.2.100.0.26.43.60.77.94", SnmpInfrastructureDiscovery.OidDot1qTpFdbPort, true));
            Assert.Null(SnmpInfrastructureDiscovery.ParseFdbIndexMac("1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77", SnmpInfrastructureDiscovery.OidDot1dTpFdbPort, false));
            Assert.Null(SnmpInfrastructureDiscovery.ParseFdbIndexMac("1.3.6.1.2.1.17.4.3.1.2.0.26.43.60.77.300", SnmpInfrastructureDiscovery.OidDot1dTpFdbPort, false));
            Assert.Null(SnmpInfrastructureDiscovery.ParseFdbIndexMac("1.3.6.1.2.1.17.4.3.1.2.0.0.0.0.0.0", SnmpInfrastructureDiscovery.OidDot1dTpFdbPort, false));
        }

        [Fact]
        public void LldpRows_AssembleIntoNeighbours()
        {
            const string b = SnmpInfrastructureDiscovery.OidLldpRemTable;
            var chassis = new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22 };
            var rows = new List<(string, byte, byte[], string)>
            {
                (b + ".4.0.5.1", SnmpBer.TagInteger, SnmpBer.IntegerContent(4), "4"),
                (b + ".5.0.5.1", SnmpBer.TagOctetString, chassis, "AA-BB-CC-00-11-22"),
                (b + ".6.0.5.1", SnmpBer.TagInteger, SnmpBer.IntegerContent(5), "5"),
                (b + ".7.0.5.1", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("Gi1/0/24"), "Gi1/0/24"),
                (b + ".9.0.5.1", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("access-sw-2"), "access-sw-2"),
                (b + ".10.0.5.1", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("Cisco IOS 15.2"), "Cisco IOS 15.2"),
                // 두 번째 이웃: 포트 ID가 MAC 하위타입(3), sysName 없음
                (b + ".4.0.7.2", SnmpBer.TagInteger, SnmpBer.IntegerContent(7), "7"),
                (b + ".5.0.7.2", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("ap-lobby"), "ap-lobby"),
                (b + ".6.0.7.2", SnmpBer.TagInteger, SnmpBer.IntegerContent(3), "3"),
                (b + ".7.0.7.2", SnmpBer.TagOctetString, new byte[] { 1, 2, 3, 4, 5, 6 }, "01-02-03-04-05-06"),
                (b + ".8.0.7.2", SnmpBer.TagOctetString, Encoding.ASCII.GetBytes("eth0"), "eth0"),
                (b + ".99.0.7.2", SnmpBer.TagInteger, SnmpBer.IntegerContent(1), "1"), // 모르는 열은 무시
                ("1.0.8802.1.1.2.1.4.2.1.1.0.7.2", SnmpBer.TagInteger, SnmpBer.IntegerContent(1), "1"), // 다른 테이블
            };
            var list = SnmpInfrastructureDiscovery.AssembleLldp(rows);
            Assert.Equal(2, list.Count);

            var n1 = list[0];
            Assert.Equal(5, n1.LocalPortNum);
            Assert.Equal("AA-BB-CC-00-11-22", n1.ChassisId);
            Assert.Equal("AA-BB-CC-00-11-22", n1.ChassisMac);
            Assert.Equal("Gi1/0/24", n1.PortId);
            Assert.Equal("access-sw-2", n1.SysName);
            Assert.Equal("Cisco IOS 15.2", n1.SysDesc);

            var n2 = list[1];
            Assert.Equal(7, n2.LocalPortNum);
            Assert.Equal("ap-lobby", n2.ChassisId);
            Assert.Null(n2.ChassisMac);
            Assert.Equal("01-02-03-04-05-06", n2.PortId);
            Assert.Equal("eth0", n2.PortDesc);
            Assert.Equal("", n2.SysName);
        }

        // ---------- 발견기 종단 간(가짜 에이전트) ----------

        private static FakeAgent SwitchAgent()
        {
            var a = new FakeAgent().Str("1.3.6.1.2.1.1.5.0", "core-sw");
            // ipNetToPhysical: IPv4 둘 + 같은 MAC의 IPv6 하나 + 멀티캐스트(버려야 함)
            a.Bytes("1.3.6.1.2.1.4.35.1.4.1.1.4.192.168.1.10", new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x10 });
            a.Bytes("1.3.6.1.2.1.4.35.1.4.1.1.4.192.168.1.11", new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x11 });
            a.Bytes("1.3.6.1.2.1.4.35.1.4.1.1.4.224.0.0.251", new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB });
            a.Bytes("1.3.6.1.2.1.4.35.1.4.1.2.16." + string.Join(".", IPAddress.Parse("fe80::10").GetAddressBytes()), new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x10 });
            a.Bytes("1.3.6.1.2.1.4.35.1.4.1.2.16." + string.Join(".", IPAddress.Parse("2001:db8::77").GetAddressBytes()), new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x77 });
            // ifName
            a.Str("1.3.6.1.2.1.31.1.1.1.1.1", "Gi1/0/1").Str("1.3.6.1.2.1.31.1.1.1.1.2", "Gi1/0/2").Str("1.3.6.1.2.1.31.1.1.1.1.24", "Gi1/0/24");
            // dot1dBasePortIfIndex: bridge port 1→if 1, 2→if 2, 24→if 24
            a.Int("1.3.6.1.2.1.17.1.4.1.2.1", 1).Int("1.3.6.1.2.1.17.1.4.1.2.2", 2).Int("1.3.6.1.2.1.17.1.4.1.2.24", 24);
            // dot1dTpFdbPort: .10 → port 1, .11 → port 2, 업링크 24에 MAC 셋
            a.Int("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.16", 1);
            a.Int("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.17", 2);
            a.Int("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.100", 24);
            a.Int("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.101", 24);
            a.Int("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.102", 24);
            // dot1qTpFdbPort (vlan 10): 새 MAC 하나
            a.Int("1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.17.34.51.68.200", 2);
            // LLDP 이웃: 로컬 포트 24 ↔ access-sw-2 Gi1/0/48, chassis MAC = ARP의 .11 호스트
            const string l = SnmpInfrastructureDiscovery.OidLldpRemTable;
            a.Int(l + ".4.0.24.1", 4).Bytes(l + ".5.0.24.1", new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x11 });
            a.Int(l + ".6.0.24.1", 5).Str(l + ".7.0.24.1", "Gi1/0/48").Str(l + ".9.0.24.1", "access-sw-2").Str(l + ".10.0.24.1", "Cisco IOS 15.2");
            a.Str("1.0.8802.1.1.2.1.3.7.1.3.24", "Gi1/0/24");
            return a;
        }

        [Fact]
        public async Task Discovery_EndToEnd_ProducesArpFdbAndLldpFacts()
        {
            FakeAgent agent = SwitchAgent();
            var d = new SnmpInfrastructureDiscovery(new[] { (Agent, "public") }, WalkerFor(agent));
            Assert.Equal("SNMP-table", d.Name);
            var facts = await d.DiscoverAsync(1000, CancellationToken.None);

            // ARP → mac + seenBy
            Assert.True(facts.ContainsKey("192.168.1.10"));
            Fact mac10 = facts["192.168.1.10"].Single(f => f.Field == FactFields.Mac);
            Assert.Equal("00-11-22-33-44-10", mac10.Value);
            Assert.Equal("SNMP-table:10.0.0.1", mac10.Source);
            Assert.Equal(Confidence.High, mac10.Confidence);
            Fact seen = facts["192.168.1.10"].Single(f => f.Field == InfrastructureFacts.SeenByField);
            Assert.Equal("10.0.0.1", seen.Value);
            Assert.Equal(Confidence.Medium, seen.Confidence);
            Assert.False(facts.ContainsKey("224.0.0.251"));

            // IPv6은 같은 MAC의 IPv4에 붙고, 짝이 없으면 v6: 키
            Assert.Contains(facts["192.168.1.10"], f => f.Field == FactFields.Ipv6 && f.Value == "fe80::10");
            Assert.True(facts.ContainsKey("v6:2001:db8::77"));
            Assert.Contains(facts["v6:2001:db8::77"], f => f.Field == FactFields.Mac && f.Value == "00-11-22-33-44-77");

            // FDB → switchPort (IP 키와 mac: 키 모두), sysName / ifName 라벨
            Fact port10 = facts["192.168.1.10"].Single(f => f.Field == FactFields.SwitchPort);
            Assert.Equal("core-sw / Gi1/0/1", port10.Value);
            Assert.Equal(Confidence.High, port10.Confidence);
            Assert.Equal("core-sw / Gi1/0/1", facts["mac:00-11-22-33-44-10"].Single(f => f.Field == FactFields.SwitchPort).Value);
            Assert.Equal("core-sw / Gi1/0/2", facts["mac:00-11-22-33-44-C8"].Single(f => f.Field == FactFields.SwitchPort).Value); // dot1q 행
            // 업링크 포트(MAC 3개)는 Medium
            Fact uplink = facts["mac:00-11-22-33-44-64"].Single(f => f.Field == FactFields.SwitchPort);
            Assert.Equal("core-sw / Gi1/0/24", uplink.Value);
            Assert.Equal(Confidence.Medium, uplink.Confidence);

            // LLDP → lldp: 키 + chassis MAC으로 IP 키에도 이름이 붙는다
            Assert.True(facts.ContainsKey("lldp:access-sw-2"));
            var lldp = facts["lldp:access-sw-2"];
            Assert.Equal("access-sw-2", lldp.Single(f => f.Field == FactFields.Name).Value);
            Assert.Equal("Cisco IOS 15.2", lldp.Single(f => f.Field == FactFields.Description).Value);
            Assert.Equal("core-sw/Gi1/0/24 ↔ Gi1/0/48", lldp.Single(f => f.Field == FactFields.SwitchPort).Value);
            Assert.Equal("00-11-22-33-44-11", lldp.Single(f => f.Field == FactFields.Mac).Value);
            Assert.Contains(facts["192.168.1.11"], f => f.Field == FactFields.Name && f.Value == "access-sw-2");
            Assert.Contains(facts["192.168.1.11"], f => f.Field == FactFields.SwitchPort && f.Value == "core-sw/Gi1/0/24 ↔ Gi1/0/48");
            Assert.Contains(facts["mac:00-11-22-33-44-11"], f => f.Field == FactFields.SwitchPort && f.Value.Contains("↔"));
        }

        [Fact]
        public async Task Discovery_FallsBackToIpNetToMedia_AndIfDescr()
        {
            var agent = new FakeAgent().Str("1.3.6.1.2.1.1.5.0", "old-router");
            agent.Bytes("1.3.6.1.2.1.4.22.1.2.1.10.1.1.5", new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x05 });
            agent.Bytes("1.3.6.1.2.1.4.22.1.2.1.10.1.1.6", Array.Empty<byte>()); // 미완성 항목
            agent.Str("1.3.6.1.2.1.2.2.1.2.3", "ether3");
            agent.Int("1.3.6.1.2.1.17.1.4.1.2.3", 3);
            agent.Int("1.3.6.1.2.1.17.4.3.1.2.222.173.190.239.0.5", 3);
            agent.RejectBulk = true; // v1류 장비

            var facts = await new SnmpInfrastructureDiscovery(new[] { (Agent, "public") }, WalkerFor(agent)).DiscoverAsync(500, CancellationToken.None);
            Assert.Equal(new[] { "10.1.1.5", "mac:DE-AD-BE-EF-00-05" }, facts.Keys.OrderBy(k => k).ToArray());
            Assert.Equal("DE-AD-BE-EF-00-05", facts["10.1.1.5"].Single(f => f.Field == FactFields.Mac).Value);
            Assert.Equal("old-router / ether3", facts["10.1.1.5"].Single(f => f.Field == FactFields.SwitchPort).Value);
        }

        [Fact]
        public async Task Discovery_SilentAgent_SkippedWithoutThrowing()
        {
            var silent = new FakeAgent { Silent = true };
            var d = new SnmpInfrastructureDiscovery(new[] { (Agent, "public"), (Agent, "public") }, WalkerFor(silent));
            Assert.Single(d.Agents); // 중복 제거
            var facts = await d.DiscoverAsync(100, CancellationToken.None);
            Assert.Empty(facts);
            Assert.Empty(await new SnmpInfrastructureDiscovery(Array.Empty<(IPAddress, string)>()).DiscoverAsync(100, CancellationToken.None));
        }

        [Fact]
        public async Task Discovery_MultipleAgents_PrefersAccessPortOverUplink()
        {
            // core: MAC X는 업링크(MAC 3개)에, access: MAC X는 접속 포트(혼자)에 보인다 → access 포트를 고른다.
            var core = new FakeAgent().Str("1.3.6.1.2.1.1.5.0", "core");
            core.Int("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.5", 9).Int("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.6", 9).Int("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.7", 9);
            var access = new FakeAgent().Str("1.3.6.1.2.1.1.5.0", "access");
            access.Int("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.5", 3).Str("1.3.6.1.2.1.31.1.1.1.1.3", "Fa0/3").Int("1.3.6.1.2.1.17.1.4.1.2.3", 3);

            var coreIp = IPAddress.Parse("10.0.0.1");
            var accessIp = IPAddress.Parse("10.0.0.2");
            var walker = new SnmpWalker(req =>
            {
                // 커뮤니티로 에이전트를 가른다
                SnmpBer.TryParse(req, out SnmpBer.Pdu pdu);
                return pdu.Community == "core" ? core.Handle(req) : access.Handle(req);
            });
            var facts = await new SnmpInfrastructureDiscovery(new[] { (coreIp, "core"), (accessIp, "access") }, walker).DiscoverAsync(500, CancellationToken.None);
            Fact port = facts["mac:00-01-02-03-04-05"].Single(f => f.Field == FactFields.SwitchPort);
            Assert.Equal("access / Fa0/3", port.Value);
            Assert.Equal("SNMP-table:10.0.0.2", port.Source);
            Assert.Equal(Confidence.High, port.Confidence);
            Assert.Equal("core / port 9", facts["mac:00-01-02-03-04-06"].Single(f => f.Field == FactFields.SwitchPort).Value);
        }

        // ---------- OS 이웃 테이블 파서 ----------

        private const string NdpSample =
            "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n" +
            "fe80::1%lo0                             (incomplete)         lo0 permanent R      \n" +
            "fe80::cb5:6cde:3293:5e1e%en0            7a:5e:35:7a:e0:bc    en0 23h51m30s S      \n" +
            "fe80::ec20:4ff:fe83:3ba8%awdl0          ee:20:4:83:3b:a8   awdl0 permanent R      \n" +
            "2001:db8:1::42                          0:23:aa:3a:82:ba     en0 1h2m3s    R      \n" +
            "ff02::1%en0                             33:33:0:0:0:1        en0 permanent R      \n";

        [Fact]
        public void ParseNdp_SkipsIncompleteAndMulticast_NormalizesMac()
        {
            var list = NeighborTableReader.ParseNdp(NdpSample);
            Assert.Equal(3, list.Count);
            Assert.Equal(("fe80::cb5:6cde:3293:5e1e", "7A-5E-35-7A-E0-BC", "en0", true), list[0]);
            Assert.Equal(("fe80::ec20:4ff:fe83:3ba8", "EE-20-04-83-3B-A8", "awdl0", true), list[1]);
            Assert.Equal(("2001:db8:1::42", "00-23-AA-3A-82-BA", "en0", true), list[2]);
            Assert.Empty(NeighborTableReader.ParseNdp(""));
        }

        private const string ArpAnSample =
            "? (169.254.169.254) at (incomplete) on en0 [ethernet]\n" +
            "? (192.168.75.1) at 0:23:aa:3a:82:ba on en0 ifscope [ethernet]\n" +
            "? (192.168.75.2) at (incomplete) on en0 ifscope [ethernet]\n" +
            "? (192.168.75.30) at 3c:22:fb:11:22:33 on en0 ifscope [ethernet]\n" +
            "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n" +
            "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0\n"; // Linux 형식

        [Fact]
        public void ParseArpAn_HandlesMacOSAndLinuxLayouts()
        {
            var list = NeighborTableReader.ParseArpAn(ArpAnSample);
            Assert.Equal(3, list.Count);
            Assert.Equal(("192.168.75.1", "00-23-AA-3A-82-BA", "en0", false), list[0]);
            Assert.Equal(("192.168.75.30", "3C-22-FB-11-22-33", "en0", false), list[1]);
            Assert.Equal(("192.168.1.1", "00-11-22-33-44-55", "eth0", false), list[2]);
        }

        private const string IpNeighSample =
            "fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE\n" +
            "2001:db8::7 dev eth0  FAILED\n" +
            "2001:db8::8 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n" +
            "2001:db8::9 dev eth0 lladdr aa:bb:cc:dd:ee:01 FAILED\n" +
            "ff02::16 dev eth0 lladdr 33:33:00:00:00:16 NOARP\n" +
            "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:02 DELAY\n" +
            "fe80::2 dev wlan0  INCOMPLETE\n" +
            "\n";

        [Fact]
        public void ParseIpNeigh_HandlesV6AndV4_SkipsFailed()
        {
            var list = NeighborTableReader.ParseIpNeigh(IpNeighSample);
            Assert.Equal(3, list.Count);
            Assert.Equal(("fe80::1", "00-11-22-33-44-55", "eth0", true), list[0]);
            Assert.Equal(("2001:db8::8", "AA-BB-CC-DD-EE-FF", "eth0", true), list[1]);
            Assert.Equal(("192.168.1.5", "AA-BB-CC-DD-EE-02", "eth0", false), list[2]);
        }

        [Fact]
        public void ParseProcArp_OnlyCompleteEntries()
        {
            const string sample =
                "IP address       HW type     Flags       HW address            Mask     Device\n" +
                "192.168.0.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n" +
                "192.168.0.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n" +
                "192.168.0.4      0x1         0x6         0a:0b:0c:0d:0e:0f     *        wlan0\n";
            var list = NeighborTableReader.ParseProcArp(sample);
            Assert.Equal(2, list.Count);
            Assert.Equal(("192.168.0.1", "00-11-22-33-44-55", "eth0", false), list[0]);
            Assert.Equal(("192.168.0.4", "0A-0B-0C-0D-0E-0F", "wlan0", false), list[1]);
        }

        // MIB_IPNET_ROW2(88바이트)를 손으로 만든다. family 2: 주소 @4, family 23: 주소 @8(16바이트). ifIndex @28, MAC @40, len @72, state @76.
        private static byte[] BuildWindowsRow(IPAddress ip, byte[] mac, int state, int ifIndex = 7)
        {
            var row = new byte[NeighborTableReader.WindowsRowSize];
            byte[] addr = ip.GetAddressBytes();
            if (addr.Length == 4) { row[0] = 2; addr.CopyTo(row, 4); }
            else { row[0] = 23; addr.CopyTo(row, 8); BitConverter.GetBytes(12).CopyTo(row, 24); }
            BitConverter.GetBytes(ifIndex).CopyTo(row, 28);
            mac.CopyTo(row, 40);
            BitConverter.GetBytes((uint)mac.Length).CopyTo(row, 72);
            BitConverter.GetBytes(state).CopyTo(row, 76);
            return row;
        }

        [Fact]
        public void WindowsRow_ParsesIpv6AndIpv4_SkipsIncomplete()
        {
            var mac = new byte[] { 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
            var v6 = NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("fe80::1a2b:3c4d:5e6f:7788"), mac, 3 /*Stale*/));
            Assert.NotNull(v6);
            Assert.Equal("fe80::1a2b:3c4d:5e6f:7788", v6!.Value.Ip);
            Assert.Equal("00-1A-2B-3C-4D-5E", v6.Value.Mac);
            Assert.Equal(7, v6.Value.InterfaceIndex);
            Assert.True(v6.Value.IsIpv6);

            var v4 = NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("192.168.1.20"), mac, 2 /*Reachable*/, 12));
            Assert.Equal(("192.168.1.20", "00-1A-2B-3C-4D-5E", 12, false), v4!.Value);

            Assert.Null(NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("192.168.1.21"), mac, 1 /*Incomplete*/)));
            Assert.Null(NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("192.168.1.22"), mac, 0 /*Unreachable*/)));
            Assert.Null(NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("ff02::1"), new byte[] { 0x33, 0x33, 0, 0, 0, 1 }, 6)));
            Assert.Null(NeighborTableReader.ParseWindowsRow(BuildWindowsRow(IPAddress.Parse("192.168.1.23"), new byte[6], 2)));
            Assert.Null(NeighborTableReader.ParseWindowsRow(new byte[10]));
        }

        [Fact]
        public void NeighborTableReader_Read_DoesNotThrow()
        {
            var list = NeighborTableReader.Read();
            Assert.NotNull(list);
            foreach (var e in list)
            {
                Assert.Matches("^[0-9A-F]{2}(-[0-9A-F]{2}){5}$", e.Mac);
                Assert.True(IPAddress.TryParse(e.Ip, out _));
            }
        }

        [Fact]
        public async Task NeighborDiscovery_JoinsIpv6ByMac_AndKeysV6Only()
        {
            var entries = new List<(string Ip, string Mac, string Interface, bool IsIpv6)>
            {
                ("192.168.1.10", "00-11-22-33-44-10", "en0", false),
                ("fe80::10", "00-11-22-33-44-10", "en0", true),
                ("2001:db8::10", "00-11-22-33-44-10", "en0", true),
                ("fe80::99", "00-11-22-33-44-99", "en0", true),
            };
            var d = new NeighborDiscovery(() => entries);
            Assert.Equal("neighbor-table", d.Name);
            var facts = await d.DiscoverAsync(100, CancellationToken.None);

            var host = facts["192.168.1.10"];
            Assert.Equal("00-11-22-33-44-10", host.Single(f => f.Field == FactFields.Mac).Value);
            Assert.Equal("os-neighbor-table", host.Single(f => f.Field == InfrastructureFacts.SeenByField).Value);
            Assert.Equal(new[] { "2001:db8::10", "fe80::10" }, host.Where(f => f.Field == FactFields.Ipv6).Select(f => f.Value).OrderBy(v => v).ToArray());
            Assert.All(host, f => Assert.Equal("neighbor-table", f.Source));

            Assert.Equal("00-11-22-33-44-99", facts["v6:fe80::99"].Single(f => f.Field == FactFields.Mac).Value);
            Assert.False(facts.ContainsKey("v6:fe80::10"));

            // 읽기 함수가 던져도 빈 결과
            Assert.Empty(await new NeighborDiscovery(() => throw new InvalidOperationException("boom")).DiscoverAsync(100, CancellationToken.None));
        }

        // ---------- 능동 ARP 프로브 ----------

        [Fact]
        public async Task ActiveArpProber_UnsupportedHere_ReturnsEmptyWithoutThrowing()
        {
            if (!OperatingSystem.IsLinux()) Assert.False(ActiveArpProber.IsSupported);
            // Linux에서는 권한에 따라 다르므로 값만 안정적인지 본다.
            Assert.Equal(ActiveArpProber.IsSupported, ActiveArpDiscovery.IsSupported);

            var targets = new[] { IPAddress.Parse("192.168.75.1"), IPAddress.Parse("192.168.75.2"), IPAddress.Parse("fe80::1") };
            var result = await ActiveArpProber.ProbeAsync(targets, 50, CancellationToken.None);
            Assert.NotNull(result);
            if (!ActiveArpProber.IsSupported) Assert.Empty(result);

            var d = new ActiveArpDiscovery();
            Assert.Equal("ARP-probe", d.Name);
            var facts = await d.DiscoverAsync(targets, 50, CancellationToken.None);
            if (!ActiveArpProber.IsSupported) Assert.Empty(facts);
            // 대상 없이(INetworkDiscovery 경로) 호출되면 항상 비어 있다.
            Assert.Empty(await d.DiscoverAsync(50, CancellationToken.None));
            Assert.Empty(await d.DiscoverAsync(Array.Empty<IPAddress>(), 50, CancellationToken.None));
        }

        [Fact]
        public void ArpFrame_WhoHasLayout_AndReplyParsing()
        {
            var srcMac = new byte[] { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
            byte[] frame = ActiveArpProber.BuildWhoHas(srcMac, new byte[] { 192, 168, 1, 2 }, new byte[] { 192, 168, 1, 50 });
            Assert.Equal(42, frame.Length);
            Assert.All(frame.Take(6), b => Assert.Equal(0xFF, b));
            Assert.Equal(srcMac, frame.Skip(6).Take(6).ToArray());
            Assert.Equal(new byte[] { 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01 }, frame.Skip(12).Take(10).ToArray());
            Assert.Equal(new byte[] { 192, 168, 1, 2 }, frame.Skip(28).Take(4).ToArray());
            Assert.Equal(new byte[] { 192, 168, 1, 50 }, frame.Skip(38).Take(4).ToArray());

            // 요청 → 응답으로 바꿔(opcode 2, 보낸 쪽 = 대상) 파싱
            byte[] reply = (byte[])frame.Clone();
            reply[21] = 2;
            new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 }.CopyTo(reply, 22);
            new byte[] { 192, 168, 1, 50 }.CopyTo(reply, 28);
            Assert.True(ActiveArpProber.TryParseArp(reply, out string ip, out string mac));
            Assert.Equal("192.168.1.50", ip);
            Assert.Equal("AA-BB-CC-DD-EE-01", mac);

            reply[13] = 0x00; // ethertype 0x0800 → ARP 아님
            Assert.False(ActiveArpProber.TryParseArp(reply, out _, out _));
            Assert.False(ActiveArpProber.TryParseArp(new byte[20], out _, out _));
        }

        [Fact]
        public void SockaddrLl_BodyLayout()
        {
            byte[] body = ActiveArpProber.BuildSockaddrLlBody(5, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            Assert.Equal(18, body.Length);
            Assert.Equal(new byte[] { 0x08, 0x06 }, body.Take(2).ToArray());            // htons(ETH_P_ARP)
            Assert.Equal(5, BitConverter.ToInt32(body, 2));                              // ifindex (호스트 순서)
            Assert.Equal(6, body[9]);                                                   // halen
            Assert.All(body.Skip(10).Take(6), b => Assert.Equal(0xFF, b));

            var ep = new ActiveArpProber.PacketEndPoint(5, new byte[] { 1, 2, 3, 4, 5, 6 });
            Assert.Equal(System.Net.Sockets.AddressFamily.Packet, ep.AddressFamily);
            Assert.Equal(5, ep.InterfaceIndex);
        }

        // ---------- MAC 정규화 ----------

        [Fact]
        public void MacNormalization_AndUsability()
        {
            Assert.Equal("00-23-AA-3A-82-BA", InfrastructureFacts.MacFromText("0:23:aa:3a:82:ba"));
            Assert.Equal("00-23-AA-3A-82-BA", InfrastructureFacts.MacFromText("00-23-AA-3A-82-BA"));
            Assert.Equal("00-23-AA-3A-82-BA", InfrastructureFacts.MacFromText("0023.aa3a.82ba"));
            Assert.Null(InfrastructureFacts.MacFromText("(incomplete)"));
            Assert.Null(InfrastructureFacts.MacFromText("00:00:00:00:00:00"));
            Assert.Null(InfrastructureFacts.MacFromText("00:11:22:33:44"));
            Assert.True(InfrastructureFacts.IsUsableMac("00-23-AA-3A-82-BA"));
            Assert.False(InfrastructureFacts.IsUsableMac("01-00-5E-00-00-FB"));
            Assert.False(InfrastructureFacts.IsUsableMac("33-33-00-00-00-01"));
            Assert.False(InfrastructureFacts.IsUsableMac("FF-FF-FF-FF-FF-FF"));
            Assert.False(InfrastructureFacts.IsUsableMac(null));
            Assert.Equal("mac:00-23-AA-3A-82-BA", InfrastructureFacts.MacKey("00-23-AA-3A-82-BA"));
        }
    }
}
