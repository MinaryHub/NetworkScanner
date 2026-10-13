using System.Collections.Generic;
using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class ScanDiffTests
    {
        private static Dictionary<string, HostState> State(params (string ip, bool alive, string mac, string ports, bool prohibited)[] rows)
        {
            var d = new Dictionary<string, HostState>();
            foreach (var r in rows) d[r.ip] = new HostState(r.alive, r.mac, r.ports, r.prohibited);
            return d;
        }

        [Fact]
        public void FirstScan_DoesNotReportEveryHostAsNew()
        {
            var baseline = State(); // 비어 있음 = 최초 스캔
            var current = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "80/", false));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            Assert.DoesNotContain(changes, c => c.Type == ScanChangeType.NewHost);
            Assert.DoesNotContain(changes, c => c.Type == ScanChangeType.NewOpenPort);
        }

        [Fact]
        public void NewlyAliveHost_IsReportedAsNewHost()
        {
            var baseline = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "", false));
            var current = State(
                ("10.0.0.1", true, "AA-BB-CC-00-00-01", "", false),
                ("10.0.0.2", true, "AA-BB-CC-00-00-02", "", false));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            Assert.Contains(changes, c => c.Type == ScanChangeType.NewHost && c.Ip == "10.0.0.2");
        }

        [Fact]
        public void HostThatWentDown_IsReportedOffline()
        {
            var baseline = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "", false));
            var current = State(("10.0.0.1", false, "AA-BB-CC-00-00-01", "", false));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            Assert.Contains(changes, c => c.Type == ScanChangeType.HostOffline && c.Ip == "10.0.0.1");
        }

        [Fact]
        public void SameIpDifferentMac_IsReportedAsMacChangeAndIsSecurityRelevant()
        {
            var baseline = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "", false));
            var current = State(("10.0.0.1", true, "AA-BB-CC-00-00-99", "", false));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            var mac = Assert.Single(changes, c => c.Type == ScanChangeType.MacChanged);
            Assert.Equal("10.0.0.1", mac.Ip);
            Assert.True(ScanDiff.IsSecurityRelevant(mac.Type));
        }

        [Fact]
        public void NewlyOpenedPort_OnKnownHost_IsReported()
        {
            var baseline = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "80/", false));
            var current = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "80/443/", false));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            var port = Assert.Single(changes, c => c.Type == ScanChangeType.NewOpenPort);
            Assert.Equal("443", port.Detail);
        }

        [Fact]
        public void ProhibitedPort_IsAlwaysReported_AndSecurityRelevant()
        {
            var baseline = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "31337/", true));
            var current = State(("10.0.0.1", true, "AA-BB-CC-00-00-01", "31337/", true));

            var changes = ScanDiff.ComputeChanges(baseline, current);

            var prohibited = Assert.Single(changes, c => c.Type == ScanChangeType.ProhibitedPort);
            Assert.True(ScanDiff.IsSecurityRelevant(prohibited.Type));
        }
    }
}
