using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KetworkScanner;
using KetworkScanner.Discovery;
using KetworkScanner.Tests.Fixtures;

namespace KetworkScanner.Tests
{
    public class FactFusionTests
    {
        [Fact]
        public void Best_PicksHighestConfidence_AndHistoryIsLowered()
        {
            var now = new HostFacts("10.0.0.1");
            now.Add(FactFields.Os, "Linux/Unix", "TTL", Confidence.Low);
            now.Add(FactFields.Os, "Windows 11", "SMB", Confidence.High);
            Assert.Equal("Windows 11", now.BestValue(FactFields.Os));

            var prev = new HostFacts("10.0.0.1");
            prev.Add(FactFields.Model, "MacBookPro18,3", "mDNS", Confidence.High);
            prev.Add(FactFields.Os, "macOS", "mDNS", Confidence.High); // 현재 스캔에 os가 있으므로 무시
            FactFusion.MergeHistory(now, prev);

            Assert.Equal("Windows 11", now.BestValue(FactFields.Os));
            Fact model = now.Best(FactFields.Model)!;
            Assert.Equal("MacBookPro18,3", model.Value);
            Assert.Equal(Confidence.Medium, model.Confidence);
            Assert.StartsWith("history:", model.Source, StringComparison.Ordinal);

            string json = now.ToJson();
            HostFacts round = HostFacts.FromJson("10.0.0.1", json);
            Assert.Equal(now.All.Count, round.All.Count);
        }

        [Fact]
        public void ApplyTo_FillsFieldsWithoutOverridingStrongerOnes()
        {
            var facts = new HostFacts("10.0.0.2");
            facts.Add(FactFields.Name, "pc7", "SMB", Confidence.High);
            facts.Add(FactFields.Os, "Windows", "SMB", Confidence.High);
            facts.Add(FactFields.OsVersion, "Windows 10 (10.0.19045)", "SMB", Confidence.High);
            facts.Add(FactFields.Vendor, "Dell", "SSDP", Confidence.High);
            facts.Add(FactFields.Model, "OptiPlex 7090", "SSDP", Confidence.High);
            facts.Add(FactFields.Mac, "AA-BB-CC-DD-EE-FF", "SNMP-table", Confidence.High);

            var info = new IPInfo { Ip = "10.0.0.2", Vendor = Localization.T("vendor.private"), SystemName = "" };
            FactFusion.ApplyTo(facts, info, m => "OUI Vendor");

            Assert.Equal("pc7", info.SystemName);
            Assert.Equal("Windows", info.OsHint);
            Assert.Equal("Windows 10 (10.0.19045)", info.OsVersion);
            Assert.Equal("OptiPlex 7090", info.Model);
            // 범주 사실이 없으면 제조사/포트 분류만 본다(여기서는 둘 다 단서가 없어 빈 칸). 모델명은 종류 열에 쓰지 않는다.
            Assert.Equal("", info.DeviceType);
            info.Ports = "9100/";
            Assert.Equal(Localization.T("dev.printer"), info.DeviceType);
            info.Ports = "";

            facts.Add(FactFields.DeviceType, "nas", "SSDP", Confidence.High);
            FactFusion.ApplyTo(facts, info, m => "OUI Vendor");
            Assert.Equal(Localization.T("dev.nas"), info.DeviceType);
            Assert.Equal("OptiPlex 7090", info.Model);
            Assert.Equal("AA-BB-CC-DD-EE-FF", info.Macaddr);
            Assert.Equal("OUI Vendor", info.Vendor); // MAC을 새로 알았으면 OUI 조회가 우선, 그 뒤 SSDP 제조사는 덮지 않음
            Assert.Contains("SMB", info.FactsJson);
        }

        [Fact]
        public void AdaptiveTimeout_UsesP95WithinBounds()
        {
            Assert.Equal(300, FactFusion.AdaptiveTimeout(new long[] { 1, 2 }, 300, 5, 2000));       // 표본 부족 → 기본값
            Assert.Equal(300, FactFusion.AdaptiveTimeout(new long[] { 5, 8, 10, 12, 15 }, 300, 5, 2000)); // p95=15 → 75 < 300
            Assert.Equal(1500, FactFusion.AdaptiveTimeout(new long[] { 50, 100, 300, 200, 250 }, 300, 5, 2000)); // p95=300 → 1500
            Assert.Equal(2000, FactFusion.AdaptiveTimeout(new long[] { 900, 950, 1000, 1200, 800 }, 300, 5, 2000)); // 상한
        }

        [Fact]
        public void ParseSnmpAgents_AcceptsCommunities()
        {
            var agents = FactFusion.ParseSnmpAgents("192.168.1.1; 10.0.0.2:secret, bogus", "public");
            Assert.Equal(2, agents.Count);
            Assert.Equal("public", agents[0].Community);
            Assert.Equal("secret", agents[1].Community);
        }

        private sealed class FakeFactProbe : IFactProbe
        {
            public string Name => "fake";
            public Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
                => Task.FromResult<IReadOnlyList<Fact>>(ip == "10.9.0.5"
                    ? new[] { new Fact(FactFields.Os, "Windows", "SMB", Confidence.High), new Fact(FactFields.OsVersion, "Windows 11 (10.0.22631)", "SMB", Confidence.High), new Fact(FactFields.Name, "WIN-5", "SMB", Confidence.High) }
                    : Array.Empty<Fact>());
        }

        private sealed class FakeDiscovery : INetworkDiscovery
        {
            public string Name => "fake-ssdp";
            public Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
                => Task.FromResult<IReadOnlyDictionary<string, IReadOnlyList<Fact>>>(new Dictionary<string, IReadOnlyList<Fact>>
                {
                    ["10.9.0.17"] = new[] { new Fact(FactFields.Model, "RT-AX88U", "SSDP", Confidence.High), new Fact(FactFields.Vendor, "ASUSTeK", "SSDP", Confidence.High) },
                    ["mac:AA-AA-AA-AA-AA-05"] = new[] { new Fact(FactFields.SwitchPort, "core-sw / Gi1/0/7", "SNMP-table:10.9.0.1", Confidence.High) },
                });
        }

        // 대상 목록을 받는 발견(능동 ARP 흉내): 엔진이 넘긴 대상을 기록하고, 그중 하나를 ARP 응답으로 살린다.
        private sealed class FakeTargetedDiscovery : ITargetedNetworkDiscovery
        {
            public IReadOnlyList<System.Net.IPAddress>? Received;
            public int UntargetedCalls;
            public string Name => "ARP-probe";
            public Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
            {
                UntargetedCalls++;
                return Task.FromResult<IReadOnlyDictionary<string, IReadOnlyList<Fact>>>(new Dictionary<string, IReadOnlyList<Fact>>());
            }
            public Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(IReadOnlyList<System.Net.IPAddress> targets, int timeoutMs, CancellationToken ct)
            {
                Received = targets;
                return Task.FromResult<IReadOnlyDictionary<string, IReadOnlyList<Fact>>>(new Dictionary<string, IReadOnlyList<Fact>>
                {
                    ["10.9.0.19"] = new[] { new Fact(FactFields.Mac, "AA-AA-AA-AA-AA-19", "ARP-probe", Confidence.High) },
                });
            }
        }

        private sealed class TestPinger : KetworkScanner.Network.IPinger
        {
            public Task<KetworkScanner.Network.PingResult?> PingAsync(System.Net.IPAddress ip, int timeoutMs, CancellationToken ct)
                => Task.FromResult<KetworkScanner.Network.PingResult?>(ip.ToString() == "10.9.0.5"
                    ? new KetworkScanner.Network.PingResult(true, 2, 0, "Success") : new KetworkScanner.Network.PingResult(false, 0, 0, "TimedOut"));
        }

        private sealed class TestArp : KetworkScanner.Platform.IArpResolver
        {
            public string? Resolve(string ipv4) => ipv4 == "10.9.0.5" ? "AA-AA-AA-AA-AA-05" : null;
        }

        [Fact]
        public async Task Engine_UsesProbesAndDiscovery_ToFillFactsAndFindAdvertisedHosts()
        {
            var config = new FakeScanConfigProvider();
            config.ScanRanges.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.9.0.1", EndIP = "10.9.0.20", Description = "" });
            var services = new ScanServices
            {
                Pinger = new TestPinger(),
                Ports = ScanServices.CreateOffline().Ports,
                Arp = new TestArp(),
                Dns = ScanServices.CreateOffline().Dns,
                Ttl = new KetworkScanner.Network.NullTtlProber(),
                IdentityDisabled = true,
                FactProbes = new IFactProbe[] { new FakeFactProbe() },
                NetworkDiscoveries = new INetworkDiscovery[] { new FakeDiscovery() },
            };
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), config, services, new ScanOptions { PingRetries = 0, ArpLiveness = false });

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            IPInfo win = engine.Items.GetItem("10.9.0.5")!;
            Assert.Equal("Windows", win.OsHint);
            Assert.Equal("Windows 11 (10.0.22631)", win.OsVersion);
            Assert.Equal("WIN-5", win.SystemName);
            Assert.Equal("core-sw / Gi1/0/7", win.SwitchPort); // MAC으로 조인된 스위치 포트

            IPInfo router = engine.Items.GetItem("10.9.0.17")!; // Ping에 답하지 않았지만 SSDP로 광고 → 살아있음
            Assert.True(router.Alive);
            Assert.Equal("MCAST", router.RountTime);
            Assert.Equal("RT-AX88U", router.Model);
            Assert.Equal("ASUSTeK", router.Vendor);
        }

        [Fact]
        public async Task Engine_PassesScanTargets_ToTargetedDiscovery()
        {
            var config = new FakeScanConfigProvider();
            config.ScanRanges.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.9.0.1", EndIP = "10.9.0.20", Description = "" });
            var arpProbe = new FakeTargetedDiscovery();
            var services = new ScanServices
            {
                Pinger = new TestPinger(),
                Ports = ScanServices.CreateOffline().Ports,
                Arp = new TestArp(),
                Dns = ScanServices.CreateOffline().Dns,
                Ttl = new KetworkScanner.Network.NullTtlProber(),
                IdentityDisabled = true,
                NetworkDiscoveries = new INetworkDiscovery[] { arpProbe },
            };
            var engine = new ScanEngine(new IPInfoList(), new OUIInfo(), config, services, new ScanOptions { PingRetries = 0, ArpLiveness = false });

            await engine.DoScanAllRange(false, "sys", CancellationToken.None);

            // 대상이 있는 경로로만 호출되고, 이번 스캔의 대역 전체(20개)가 그대로 전달된다.
            Assert.Equal(0, arpProbe.UntargetedCalls);
            Assert.NotNull(arpProbe.Received);
            Assert.Equal(20, arpProbe.Received!.Count);
            Assert.Equal("10.9.0.1", arpProbe.Received[0].ToString());
            Assert.Equal("10.9.0.20", arpProbe.Received[19].ToString());

            // ARP 응답으로만 발견된 호스트는 살아있는 것으로 올라온다(MAC 포함).
            IPInfo viaArp = engine.Items.GetItem("10.9.0.19")!;
            Assert.True(viaArp.Alive);
            Assert.Equal("MCAST", viaArp.RountTime);
            Assert.Equal("AA-AA-AA-AA-AA-19", viaArp.Macaddr);
        }
    }
}
