using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using KetworkScanner;
using KetworkScanner.History;
using KetworkScanner.Secrets;
using KetworkScanner.Support;

namespace KetworkScanner.Tests
{
    // 프로필 / 설정 내보내기·가져오기 / 진단 번들 / 이력 보존·백업.
    public class OperationsTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "nstest-ops-" + Guid.NewGuid().ToString("N"));

        public OperationsTests()
        {
            Directory.CreateDirectory(_root);
            UserDataPaths.OverrideRoot = _root;
            AppSettingsStore.SecretStore = new EncryptedFileSecretStore(_root);
        }

        public void Dispose()
        {
            UserDataPaths.OverrideRoot = null;
            AppSettingsStore.SecretStore = null!;
            try { Directory.Delete(_root, true); } catch { }
        }

        [Fact]
        public void Profiles_ChangeOnlyScanBehaviour()
        {
            var settings = new AppSettingsData { ScanParallelism = 64, ScanProfile = "quick" };
            ScanOptions quick = ScanOptions.FromSettings(settings);
            Assert.Equal(128, quick.Parallelism);
            Assert.False(quick.IdentityProbes);
            Assert.False(quick.AssessVulnerabilities);
            Assert.Empty(quick.ExtraPorts);

            settings.ScanProfile = "thorough";
            ScanOptions deep = ScanOptions.FromSettings(settings);
            Assert.Equal(32, deep.Parallelism);
            Assert.True(deep.IdentityProbes);
            Assert.Contains(3389, deep.ExtraPorts);

            settings.ScanProfile = "standard";
            Assert.Equal(64, ScanOptions.FromSettings(settings).Parallelism);
            Assert.Equal(ScanProfileKind.Standard, ScanProfiles.Parse("whatever"));
        }

        [Fact]
        public void Profiles_AppliedInSequence_DoNotLeakPreviousValues()
        {
            // 같은 옵션 객체에 quick → thorough를 연달아 적용하면 quick이 끈 심층 발견/식별/평가가 다시 켜져야 한다.
            var options = new ScanOptions();
            ScanProfiles.Apply(options, ScanProfileKind.Quick);
            Assert.False(options.DeepDiscovery);
            Assert.Equal(ScanProfileKind.Quick, options.Profile);

            ScanProfiles.Apply(options, ScanProfileKind.Thorough);
            Assert.True(options.DeepDiscovery);
            Assert.True(options.IdentityProbes);
            Assert.True(options.BannerGrab);
            Assert.True(options.AssessVulnerabilities);
            Assert.Equal(ScanProfileKind.Thorough, options.Profile);
            Assert.Equal("thorough", ScanProfiles.Name(options.Profile));
            Assert.NotEmpty(options.ExtraPorts);

            // thorough → standard: 타임아웃/추가 포트가 기본값으로 돌아온다.
            ScanProfiles.Apply(options, ScanProfileKind.Standard);
            var defaults = new ScanOptions();
            Assert.Equal(defaults.PingTimeoutMs, options.PingTimeoutMs);
            Assert.Equal(defaults.PortTimeoutMs, options.PortTimeoutMs);
            Assert.Equal(defaults.DnsTimeoutMs, options.DnsTimeoutMs);
            Assert.Empty(options.ExtraPorts);
            Assert.True(options.DeepDiscovery);
            Assert.Equal(ScanProfileKind.Standard, options.Profile);
        }

        [Fact]
        public void ExportImport_RoundTripsWithoutSecrets_AndKeepsLocalOnlyValues()
        {
            var data = new AppSettingsData { SystemName = "site-A", ScanProfile = "thorough", UsageNoticeAccepted = true, IpListColumnWidths = "1,2" };
            data.Upload.Enabled = true;
            data.Upload.Host = "h";
            data.Upload.Password = "secret!";
            AppSettingsStore.SaveSettings(data);
            var ranges = new ScanRangeList();
            ranges.AddItem(new ScanRangeInfo { StartIP = "10.1.0.1", EndIP = "10.1.0.50", Description = "lab" });
            AppSettingsStore.SaveScanRanges(ranges);

            string file = Path.Combine(_root, "export.json");
            AppSettingsStore.Export(file);
            string json = File.ReadAllText(file);
            Assert.DoesNotContain("secret!", json);
            Assert.Contains("site-A", json);
            Assert.Contains("10.1.0.50", json);

            // 다른 값으로 바꾼 뒤 가져오기: 내보낸 값으로 돌아오되, 컬럼 너비·고지 확인·비밀은 현재 것을 유지
            var changed = AppSettingsStore.LoadSettings();
            changed.SystemName = "changed";
            changed.IpListColumnWidths = "9,9";
            AppSettingsStore.SaveSettings(changed);

            AppSettingsStore.Import(file);
            AppSettingsData loaded = AppSettingsStore.LoadSettings();
            Assert.Equal("site-A", loaded.SystemName);
            Assert.Equal("9,9", loaded.IpListColumnWidths);
            Assert.True(loaded.UsageNoticeAccepted);
            Assert.Equal("secret!", loaded.Upload.Password);
            Assert.Single(AppSettingsStore.LoadScanRanges());
        }

        [Fact]
        public void DiagnosticBundle_ContainsInfoSettingsAndLogs_ButNoSecrets()
        {
            var data = new AppSettingsData { SystemName = "diag" };
            data.Upload.Password = "topsecret";
            AppSettingsStore.SaveSettings(data);
            AppLogger.LogInfo("test", "hello diag");
            using var history = new ScanHistoryStore(Path.Combine(_root, "history.db"));

            string zip = DiagnosticBundle.Create(Path.Combine(_root, "diag.zip"), history: history);

            using ZipArchive archive = ZipFile.OpenRead(zip);
            var names = archive.Entries.Select(e => e.FullName).ToList();
            Assert.Contains("info.txt", names);
            Assert.Contains("settings.json", names);
            Assert.Contains(names, n => n.StartsWith("logs/", StringComparison.Ordinal));
            Assert.DoesNotContain(names, n => n.Contains("secrets", StringComparison.OrdinalIgnoreCase));
            foreach (var e in archive.Entries)
            {
                using var r = new StreamReader(e.Open());
                Assert.DoesNotContain("topsecret", r.ReadToEnd());
            }
        }

        [Fact]
        public void HistoryMaintenance_PrunesOldScans_AndRotatesBackups()
        {
            using var store = new ScanHistoryStore(Path.Combine(_root, "history.db"));
            var now = DateTimeOffset.UtcNow;
            var host = new[] { new ScanHostRecord("10.0.0.1", true, "", "", "", "", "", "", 0, false) };
            store.RecordScan(new ScanRecord(now.AddDays(-400), now.AddDays(-400), "old", false, host));
            store.RecordScan(new ScanRecord(now, now, "new", false, host));

            var r1 = HistoryMaintenance.RunIfDue(store, retentionDays: 180, backupsToKeep: 2, now);
            Assert.NotNull(r1);
            Assert.Equal(1, r1!.Pruned);
            Assert.NotNull(r1.BackupPath);
            Assert.Single(store.ListScans());

            // 같은 날 다시 호출하면 건너뛴다
            Assert.Null(HistoryMaintenance.RunIfDue(store, 180, 2, now.AddHours(1)));

            // 강제 실행 두 번 더 → 백업 3개 중 2개만 남는다
            HistoryMaintenance.Run(store, 180, 2, now.AddSeconds(1));
            HistoryMaintenance.Run(store, 180, 2, now.AddSeconds(2));
            Assert.Equal(2, HistoryMaintenance.ListBackups().Count);
        }
    }
}
