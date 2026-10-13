using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KetworkScanner;
using KetworkScanner.Alerts;
using KetworkScanner.History;

namespace KetworkScanner.Tests
{
    public class AlertAndAssetTests : IDisposable
    {
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "nstest-alerts-" + Guid.NewGuid().ToString("N"));
        private readonly ScanHistoryStore _store;

        public AlertAndAssetTests()
        {
            Directory.CreateDirectory(_dir);
            _store = new ScanHistoryStore(Path.Combine(_dir, "h.db"));
        }

        public void Dispose()
        {
            _store.Dispose();
            try { Directory.Delete(_dir, true); } catch { }
        }

        private static HostState Up(string mac = "AA-AA-AA-AA-AA-AA", string ports = "", bool prohibited = false, int risk = 0)
            => new(true, mac, ports, prohibited, risk);

        [Theory]
        [InlineData("Mon-Fri 22:00-06:00", "2026-10-13 23:00", true)]   // 화요일 밤
        [InlineData("Mon-Fri 22:00-06:00", "2026-10-14 05:30", true)]   // 수요일 새벽(자정 넘김)
        [InlineData("Mon-Fri 22:00-06:00", "2026-10-14 12:00", false)]
        [InlineData("Sat,Sun", "2026-10-11 15:00", true)]                // 일요일 하루 종일
        [InlineData("Sat,Sun", "2026-10-12 15:00", false)]
        [InlineData("* 12:00-13:00", "2026-10-12 12:30", true)]
        public void MaintenanceWindow_Contains(string spec, string when, bool expected)
        {
            Assert.True(MaintenanceWindow.TryParse(spec, out var w));
            Assert.Equal(expected, w!.Contains(DateTime.Parse(when, System.Globalization.CultureInfo.InvariantCulture)));
        }

        [Fact]
        public void MaintenanceWindow_ParseList_ReportsInvalidEntries()
        {
            var (ok, bad) = MaintenanceWindow.ParseList("Mon-Fri 22:00-06:00; nonsense 99:99; Sat");
            Assert.Equal(2, ok.Count);
            Assert.Single(bad);
        }

        [Fact]
        public void UnapprovedHost_IsReported_OnlyWhenPolicyEnabled_AndApprovedMacMismatchAlways()
        {
            var baseline = new Dictionary<string, HostState> { ["10.0.0.1"] = Up() };
            var current = new Dictionary<string, HostState>
            {
                ["10.0.0.1"] = Up(mac: "BB-BB-BB-BB-BB-BB"),
                ["10.0.0.2"] = Up(mac: "CC-CC-CC-CC-CC-CC"),
            };
            var approved = new Dictionary<string, ApprovedHost> { ["10.0.0.1"] = new("10.0.0.1", "AA-AA-AA-AA-AA-AA", "ops") };

            var off = ScanDiff.ComputeChanges(baseline, current, approved, AssetPolicy.Disabled);
            Assert.DoesNotContain(off, c => c.Type == ScanChangeType.UnapprovedHost);
            Assert.Contains(off, c => c.Type == ScanChangeType.ApprovedMacMismatch && c.Ip == "10.0.0.1");

            var on = ScanDiff.ComputeChanges(baseline, current, approved, new AssetPolicy(true));
            Assert.Contains(on, c => c.Type == ScanChangeType.UnapprovedHost && c.Ip == "10.0.0.2");
        }

        [Fact]
        public void HighRisk_IsReported_AboveThreshold()
        {
            var current = new Dictionary<string, HostState> { ["10.0.0.9"] = Up(risk: 55) };
            var changes = ScanDiff.ComputeChanges(new Dictionary<string, HostState>(), current, null, new AssetPolicy(false, 40));
            Assert.Contains(changes, c => c.Type == ScanChangeType.HighRisk && c.Detail == "55");
            Assert.Empty(ScanDiff.ComputeChanges(new Dictionary<string, HostState>(), current, null, new AssetPolicy(false, 60)));
        }

        [Fact]
        public void Store_ApprovalAndMeta_RoundTrip()
        {
            var now = DateTimeOffset.UtcNow;
            _store.RecordScan(new ScanRecord(now, now, "sys", false, new[]
            {
                new ScanHostRecord("10.0.0.1", true, "AA-AA-AA-AA-AA-AA", "Acme", "h1", "22/", "", "1", 64, false),
            }));

            Assert.Equal(1, _store.SetApproved(new[] { "10.0.0.1" }, true, now));
            Assert.True(_store.SetHostMeta("10.0.0.1", "ops-team", "server,critical", null));

            var approved = _store.GetApprovedHosts();
            Assert.Equal("AA-AA-AA-AA-AA-AA", approved["10.0.0.1"].ApprovedMac); // 승인 시점의 MAC 고정
            Assert.Equal("ops-team", approved["10.0.0.1"].Owner);

            var inv = _store.GetInventory().Single();
            Assert.True(inv.Approved);
            Assert.Equal("server,critical", inv.Tags);

            _store.SetApproved(new[] { "10.0.0.1" }, false, now);
            Assert.Empty(_store.GetApprovedHosts());
            Assert.Equal("ops-team", _store.GetInventory().Single().Owner); // 승인 해제해도 메타는 유지
        }

        [Fact]
        public void AlertManager_DedupesAcksAndResolves()
        {
            var settings = new AlertSettings { RenotifyAfterHours = 24 };
            var mgr = new AlertManager(_store, settings);
            var t0 = new DateTimeOffset(2026, 10, 12, 10, 0, 0, TimeSpan.Zero);
            var changes = new List<ScanChange>
            {
                new(ScanChangeType.ProhibitedPort, "10.0.0.5", "31337/"),
                new(ScanChangeType.NewHost, "10.0.0.6", "new"), // 보안 무관 → securityOnly면 제외
            };

            AlertOutcome first = mgr.Process(changes, t0, securityOnly: true);
            Assert.Single(first.ToNotify);
            Assert.Equal(ScanChangeType.ProhibitedPort, first.ToNotify[0].Type);

            // 1시간 뒤 같은 사건: 재알림 간격(24h) 안이라 억제, 횟수만 누적
            AlertOutcome second = mgr.Process(changes, t0.AddHours(1), securityOnly: true);
            Assert.Empty(second.ToNotify);
            Assert.Single(second.Suppressed);
            Assert.Equal(2, second.Suppressed[0].Count);

            // 25시간 뒤: 재알림
            AlertOutcome third = mgr.Process(changes, t0.AddHours(25), securityOnly: true);
            Assert.Single(third.ToNotify);

            // 확인(ack) 후에는 보내지 않음
            long id = third.ToNotify[0].Id;
            _store.SetAlertState(id, AlertState.Acknowledged);
            AlertOutcome fourth = mgr.Process(changes, t0.AddHours(50), securityOnly: true);
            Assert.Empty(fourth.ToNotify);

            // 조건이 사라지면 자동 해결
            AlertOutcome fifth = mgr.Process(new List<ScanChange>(), t0.AddHours(51), securityOnly: true);
            Assert.Equal(1, fifth.Resolved);
            Assert.Equal(AlertState.Resolved, _store.GetAlertByKey("ProhibitedPort|10.0.0.5")!.State);

            // 다시 나타나면 open으로 돌아오고 알림
            AlertOutcome sixth = mgr.Process(changes, t0.AddHours(80), securityOnly: true);
            Assert.Single(sixth.ToNotify);
            Assert.Equal(AlertState.Open, sixth.ToNotify[0].State);
        }

        [Fact]
        public void AlertManager_SuppressesDuringMaintenance_AndHonoursSnooze()
        {
            var settings = new AlertSettings { RenotifyAfterHours = 1, MaintenanceWindows = "Mon-Fri 22:00-06:00" };
            var mgr = new AlertManager(_store, settings);
            var changes = new List<ScanChange> { new(ScanChangeType.MacChanged, "10.0.0.7", "A → B") };

            // 점검 시간대(현지 시각 기준) — 테스트 머신 시간대와 무관하게 로컬 시각을 직접 만든다.
            var local = new DateTime(2026, 10, 13, 23, 30, 0, DateTimeKind.Local); // 화요일 23:30
            var during = new DateTimeOffset(local);
            AlertOutcome inWindow = mgr.Process(changes, during, securityOnly: true);
            Assert.True(inWindow.InMaintenance);
            Assert.Empty(inWindow.ToNotify);
            Assert.Single(inWindow.Active);

            var later = new DateTimeOffset(new DateTime(2026, 10, 14, 9, 0, 0, DateTimeKind.Local));
            AlertOutcome after = mgr.Process(changes, later, securityOnly: true);
            Assert.Single(after.ToNotify);

            _store.SetAlertState(after.ToNotify[0].Id, AlertState.Snoozed, later.AddHours(5));
            Assert.Empty(mgr.Process(changes, later.AddHours(3), securityOnly: true).ToNotify);
            Assert.Single(mgr.Process(changes, later.AddHours(6), securityOnly: true).ToNotify); // 스누즈 만료
        }

        [Fact]
        public void Store_BackupTo_CreatesReadableCopy()
        {
            var now = DateTimeOffset.UtcNow;
            _store.RecordScan(new ScanRecord(now, now, "sys", false, new[] { new ScanHostRecord("10.0.0.1", true, "", "", "", "", "", "", 0, false) }));
            string copy = Path.Combine(_dir, "backup.db");

            _store.BackupTo(copy);

            using var restored = new ScanHistoryStore(copy);
            Assert.Single(restored.ListScans());
        }
    }
}
