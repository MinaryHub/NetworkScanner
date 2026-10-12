using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner;
using NetworkScanner.History;
using NetworkScanner.Network;
using NetworkScanner.Platform;
using NetworkScanner.Tests.Fixtures;

namespace NetworkScanner.Tests
{
    // 네트워크에 전혀 나가지 않는 가짜 프로브로 엔진의 전체 흐름(탐지→부가 조회→변화 감지→CSV→이력)을 검증한다.
    public class ScanEngineIntegrationTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "nstest-engine-" + Guid.NewGuid().ToString("N"));

        public ScanEngineIntegrationTests()
        {
            Directory.CreateDirectory(_root);
            UserDataPaths.OverrideRoot = _root;
        }

        public void Dispose()
        {
            UserDataPaths.OverrideRoot = null;
            try { Directory.Delete(_root, true); } catch { }
        }

        private sealed class FakePinger : IPinger
        {
            public HashSet<string> Alive { get; } = new();
            public int Calls;
            public Task<PingResult?> PingAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
            {
                Interlocked.Increment(ref Calls);
                string s = ip.ToString();
                return Task.FromResult<PingResult?>(Alive.Contains(s) ? new PingResult(true, 3, 64, "Success") : new PingResult(false, 0, 0, "TimedOut"));
            }
        }

        private sealed class FakePorts : IPortProber
        {
            public Dictionary<string, HashSet<int>> Open { get; } = new();
            public Task<bool> IsOpenAsync(string ip, int port, int timeoutMs, CancellationToken ct)
                => Task.FromResult(Open.TryGetValue(ip, out var set) && set.Contains(port));
            public Task<string> GrabBannerAsync(string ip, int port, int timeoutMs, CancellationToken ct)
                => Task.FromResult(port == 22 ? "SSH-2.0-fake" : "");
        }

        private sealed class FakeArp : IArpResolver
        {
            public Dictionary<string, string> Macs { get; } = new();
            public string? Resolve(string ipv4) => Macs.TryGetValue(ipv4, out var m) ? m : null;
        }

        private static FakeScanConfigProvider Config(bool ports = true)
        {
            var c = new FakeScanConfigProvider();
            c.ScanRanges.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.9.0.1", EndIP = "10.9.0.20", Description = "" });
            c.ProhibitPortList.Add(new RefPortInfo { Protocol = "tcp", PortNo = 31337, Portname = "Back Orifice" });
            c.UsePortChecking = ports;
            c.PortList = "22/80/31337";
            return c;
        }

        [Fact]
        public async Task FullScan_DiscoversHosts_EnrichesThem_AndFlagsProhibitedPorts()
        {
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            pinger.Alive.Add("10.9.0.7");
            var ports = new FakePorts();
            ports.Open["10.9.0.5"] = new HashSet<int> { 22, 80 };
            ports.Open["10.9.0.7"] = new HashSet<int> { 31337 };
            var arp = new FakeArp();
            arp.Macs["10.9.0.5"] = "00-23-AA-11-22-33";

            var services = ScanServices.CreateOffline(pinger, ports, arp);
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(), services);
            engine.InitFromConfig();

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.True(pinger.Calls >= 20); // 재시도 포함
            Assert.Equal(2, engine.Items.Count);
            IPInfo h5 = engine.Items.GetItem("10.9.0.5")!;
            Assert.True(h5.Alive);
            Assert.Equal("22/80/", h5.Ports);
            Assert.Equal("00-23-AA-11-22-33", h5.Macaddr);
            Assert.Equal("SSH-2.0-fake", h5.Service);
            Assert.False(h5.HasProhibitedPort);

            IPInfo h7 = engine.Items.GetItem("10.9.0.7")!;
            Assert.True(h7.HasProhibitedPort);
            Assert.Equal("warn", h7.StatusKey);
        }

        [Fact]
        public async Task SecondScan_ReportsChanges_NewHost_Offline_And_NewPort()
        {
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            pinger.Alive.Add("10.9.0.6");
            var ports = new FakePorts();
            ports.Open["10.9.0.5"] = new HashSet<int> { 22 };
            var services = ScanServices.CreateOffline(pinger, ports);
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(), services);
            engine.InitFromConfig();

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            IReadOnlyList<ScanChange>? reported = null;
            engine.ScanChangesDetected += c => reported = c;

            // 두 번째 스캔: .6 오프라인, .9 신규, .5에 80 포트 새로 열림
            pinger.Alive.Remove("10.9.0.6");
            pinger.Alive.Add("10.9.0.9");
            ports.Open["10.9.0.5"].Add(80);
            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.NotNull(reported);
            Assert.Contains(reported!, c => c.Type == ScanChangeType.HostOffline && c.Ip == "10.9.0.6");
            Assert.Contains(reported!, c => c.Type == ScanChangeType.NewHost && c.Ip == "10.9.0.9");
            Assert.Contains(reported!, c => c.Type == ScanChangeType.NewOpenPort && c.Ip == "10.9.0.5" && c.Detail == "80");
        }

        [Fact]
        public async Task WriteIPInfo_ThenLoadIPInfo_RoundTripsAllFieldsIncludingCommas()
        {
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            var services = ScanServices.CreateOffline(pinger);
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);
            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            IPInfo host = engine.Items.GetItem("10.9.0.5")!;
            host.SystemName = "Printer, 3F";
            host.Description = "=HYPERLINK(\"x\")"; // CSV 인젝션 시도
            host.Service = "HTTP: nginx";
            host.Ttl = 64;

            await engine.WriteIPInfo(false, "sys");
            string csv = Directory.GetFiles(ScanEngine.GetEnvDirectory(), "*.csv").Single();
            string text = File.ReadAllText(csv);
            Assert.Contains("\"Printer, 3F\"", text);
            Assert.Contains("'=HYPERLINK", text); // 수식 무력화

            var engine2 = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);
            engine2.LoadIPInfo(csv);
            IPInfo loaded = engine2.Items.GetItem("10.9.0.5")!;
            Assert.Equal("Printer, 3F", loaded.SystemName);
            Assert.Equal("=HYPERLINK(\"x\")", loaded.Description);
            Assert.Equal("HTTP: nginx", loaded.Service);
            Assert.Equal(64, loaded.Ttl);
            Assert.True(loaded.Alive);
        }

        [Fact]
        public void LoadIPInfo_ReadsLegacyNineColumnFile()
        {
            string path = Path.Combine(_root, "legacy.csv");
            File.WriteAllText(path, "IPAddress,Port,SystemName,Description,Commitdate,Alive,MacAddress,Vendor,RoundTime\n" +
                                    "192.168.0.10,22/80/,host,note,2024/01/01 00:00:00,True,AA-BB-CC-DD-EE-FF,Acme,3\n");
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(), ScanServices.CreateOffline());

            engine.LoadIPInfo(path);

            IPInfo h = engine.Items.GetItem("192.168.0.10")!;
            Assert.Equal("Acme", h.Vendor);
            Assert.True(h.Alive);
            Assert.Equal("", h.Service);
        }

        [Fact]
        public async Task Scan_RecordsHistory_AndUsesItAsBaselineAfterRestart()
        {
            string db = Path.Combine(_root, "h.db");
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            using var history = new ScanHistoryStore(db);
            var services = new ScanServices { Pinger = pinger, Ports = new FakePorts(), Arp = new FakeArp(), Dns = ScanServices.CreateOffline().Dns, History = history, IdentityDisabled = true, Ttl = new NetworkScanner.Network.NullTtlProber() };

            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);
            await engine.DoScanAllRange(false, "sys", CancellationToken.None);
            Assert.Single(history.ListScans());

            // "재시작": 빈 목록으로 새 엔진을 만들어도 이력 DB를 기준선으로 써서 오프라인 전환을 감지한다.
            pinger.Alive.Clear();
            pinger.Alive.Add("10.9.0.8");
            var engine2 = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);
            IReadOnlyList<ScanChange>? reported = null;
            engine2.ScanChangesDetected += c => reported = c;
            await engine2.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.NotNull(reported);
            Assert.Contains(reported!, c => c.Type == ScanChangeType.HostOffline && c.Ip == "10.9.0.5");
            Assert.Contains(reported!, c => c.Type == ScanChangeType.NewHost && c.Ip == "10.9.0.8");
            Assert.Equal(2, history.ListScans().Count);
        }

        [Fact]
        public async Task Scan_FillsDescriptionFromInventoryNote_AndPersistsEditedDescriptions()
        {
            string db = Path.Combine(_root, "notes.db");
            using var history = new ScanHistoryStore(db);
            history.SetHostNotes(new[] { new KeyValuePair<string, string>("10.9.0.5", "프린터 옆 PC") });

            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            pinger.Alive.Add("10.9.0.7");
            var services = new ScanServices { Pinger = pinger, Ports = new FakePorts(), Arp = new FakeArp(), Dns = ScanServices.CreateOffline().Dns, History = history, IdentityDisabled = true, Ttl = new NetworkScanner.Network.NullTtlProber() };
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            // 인벤토리 비고 → 새로 발견된 호스트의 비어 있는 Description.
            Assert.Equal("프린터 옆 PC", engine.Items.GetItem("10.9.0.5")!.Description);
            Assert.Equal("", engine.Items.GetItem("10.9.0.7")!.Description);

            // 사용자가 편집한 Description은 저장(CSV) 시 hosts.note로 간다. 비어 있는 값은 쓰지 않는다.
            engine.Items.GetItem("10.9.0.7")!.Description = "방문자 노트북";
            engine.Items.GetItem("10.9.0.5")!.Description = "";
            await engine.WriteIPInfo(false, "sys");
            var notes = history.GetHostNotes();
            Assert.Equal("방문자 노트북", notes["10.9.0.7"]);
            Assert.Equal("프린터 옆 PC", notes["10.9.0.5"]);

            // 다음 스캔이 끝나면 그 사이 바뀐 Description도 저장된다.
            engine.Items.GetItem("10.9.0.7")!.Description = "방문자 노트북(2)";
            await engine.DoScanAllRange(false, "sys", CancellationToken.None);
            Assert.Equal("방문자 노트북(2)", history.GetHostNotes()["10.9.0.7"]);

            // CSV를 다시 읽을 때 비어 있는 Description은 인벤토리 비고로 채워진다.
            string csv = Directory.GetFiles(ScanEngine.GetEnvDirectory(), "*.csv").Single();
            var engine2 = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), services);
            engine2.LoadIPInfo(csv);
            Assert.Equal("프린터 옆 PC", engine2.Items.GetItem("10.9.0.5")!.Description);
            Assert.Equal("방문자 노트북", engine2.Items.GetItem("10.9.0.7")!.Description); // CSV에 있던 값이 우선
        }

        [Fact]
        public async Task Scan_CountsHostsKnownToArpCache_AsAlive_WhenPingAndTcpFail()
        {
            // 절전 중인 폰처럼 ICMP/TCP에 답하지 않아도 ARP 캐시에 MAC이 있으면 살아있는 것으로 본다(응답시간 "ARP").
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            var arp = new FakeArp();
            arp.Macs["10.9.0.5"] = "AA-AA-AA-AA-AA-01";
            arp.Macs["10.9.0.12"] = "AA-AA-AA-AA-AA-02";
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), ScanServices.CreateOffline(pinger, arp: arp),
                new ScanOptions { PingRetries = 1, ArpLiveness = true, MeasureTtl = false });

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.Equal(2, engine.Items.Count);
            IPInfo viaArp = engine.Items.GetItem("10.9.0.12")!;
            Assert.True(viaArp.Alive);
            Assert.Equal("ARP", viaArp.RountTime);
            Assert.Equal("AA-AA-AA-AA-AA-02", viaArp.Macaddr);
            Assert.True(pinger.Calls >= 20 + 19); // 재시도 1회 포함
        }

        [Fact]
        public async Task Scan_RefusesRangesAboveMaxTargets()
        {
            var config = Config(ports: false);
            config.ScanRanges.Clear();
            config.ScanRanges.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.0.0.0", EndIP = "10.0.255.255", Description = "" });
            var pinger = new FakePinger();
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), config, ScanServices.CreateOffline(pinger), new ScanOptions { MaxTargets = 1000 });
            string? last = null;
            engine.Message += m => last = m;

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.Equal(0, pinger.Calls);
            Assert.Contains("1000", last);
        }

        [Fact]
        public async Task PortCheck_OnSingleHost_UpdatesPortsAndProhibitedFlag()
        {
            var pinger = new FakePinger();
            pinger.Alive.Add("10.9.0.5");
            var ports = new FakePorts();
            ports.Open["10.9.0.5"] = new HashSet<int> { 31337 };
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), Config(ports: false), ScanServices.CreateOffline(pinger, ports));
            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            Assert.True(engine.StartCheckProhibitPortList("10.9.0.5"));
            await engine.Scanning!;

            IPInfo h = engine.Items.GetItem("10.9.0.5")!;
            Assert.Equal("31337/", h.Ports);
            Assert.True(h.HasProhibitedPort);
        }
    }
}
