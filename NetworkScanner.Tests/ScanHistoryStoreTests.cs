using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using NetworkScanner;
using NetworkScanner.History;

namespace NetworkScanner.Tests
{
    public class ScanHistoryStoreTests : IDisposable
    {
        private readonly string _dir;
        private readonly string _dbPath;

        public ScanHistoryStoreTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "nsc-history-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
            _dbPath = Path.Combine(_dir, "history.db");
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private static readonly DateTimeOffset T1 = new(2026, 1, 10, 9, 0, 0, TimeSpan.Zero);
        private static readonly DateTimeOffset T2 = new(2026, 1, 11, 9, 0, 0, TimeSpan.Zero);

        private static ScanHostRecord Host(string ip, bool alive, string mac = "", string ports = "", bool prohibited = false, string name = "")
            => new(ip, alive, mac, "Vendor", name, ports, "", alive ? "1ms" : "", alive ? 64 : 0, prohibited);

        // 첫 스캔: 2대 살아있음. 둘째 스캔: 10.0.0.2 죽고, 10.0.0.3 새로 등장(위험 포트).
        private static ScanRecord Scan1() => new(T1, T1.AddMinutes(1), "sys-a", false, new List<ScanHostRecord>
        {
            Host("10.0.0.2", true, "AA-BB-CC-00-00-02", "80/443/"),
            Host("10.0.0.1", true, "AA-BB-CC-00-00-01", "22/"),
        });

        private static ScanRecord Scan2() => new(T2, T2.AddMinutes(1), "sys-a", true, new List<ScanHostRecord>
        {
            Host("10.0.0.1", true, "AA-BB-CC-00-00-01", "22/8080/"),
            Host("10.0.0.2", false),
            Host("10.0.0.3", true, "AA-BB-CC-00-00-03", "31337/", prohibited: true, name: "evil"),
        });

        [Fact]
        public void RecordScan_ListScans_NewestFirstWithCounts()
        {
            using var store = new ScanHistoryStore(_dbPath);
            long id1 = store.RecordScan(Scan1());
            long id2 = store.RecordScan(Scan2());

            var scans = store.ListScans();

            Assert.Equal(2, scans.Count);
            Assert.Equal(id2, scans[0].Id);
            Assert.Equal(id1, scans[1].Id);

            Assert.Equal(T2, scans[0].StartedAt);
            Assert.Equal(3, scans[0].Total);
            Assert.Equal(2, scans[0].Alive);
            Assert.Equal(1, scans[0].Prohibited);
            Assert.True(scans[0].Scheduled);

            Assert.Equal(2, scans[1].Total);
            Assert.Equal(2, scans[1].Alive);
            Assert.Equal(0, scans[1].Prohibited);
            Assert.False(scans[1].Scheduled);
            Assert.Equal("sys-a", scans[1].SystemName);

            Assert.Single(store.ListScans(limit: 1));
        }

        [Fact]
        public void GetInventory_TracksFirstSeenLastSeenAndSeenCount_SortedByIp()
        {
            using var store = new ScanHistoryStore(_dbPath);
            store.RecordScan(Scan1());
            store.RecordScan(Scan2());

            var inv = store.GetInventory();

            Assert.Equal(new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3" }, inv.Select(h => h.Ip).ToArray());

            var h1 = inv[0];
            Assert.Equal(T1, h1.FirstSeen);
            Assert.Equal(T2, h1.LastSeen);
            Assert.Equal(T2, h1.LastAliveAt);
            Assert.Equal(2, h1.SeenCount);
            Assert.True(h1.LastAlive);
            Assert.Equal("22/8080/", h1.LastPorts);

            // 둘째 스캔에서 죽었어도 마지막으로 알던 MAC/포트는 유지, last_alive_at은 첫 스캔 시각.
            var h2 = inv[1];
            Assert.False(h2.LastAlive);
            Assert.Equal(T1, h2.LastAliveAt);
            Assert.Equal("AA-BB-CC-00-00-02", h2.LastMac);
            Assert.Equal("80/443/", h2.LastPorts);
            Assert.Equal(2, h2.SeenCount);

            var h3 = inv[2];
            Assert.Equal(T2, h3.FirstSeen);
            Assert.Equal(1, h3.SeenCount);
            Assert.Equal("evil", h3.LastName);
        }

        [Fact]
        public void GetInventory_SortsByUInt32NotString()
        {
            using var store = new ScanHistoryStore(_dbPath);
            store.RecordScan(new ScanRecord(T1, T1, "", false, new List<ScanHostRecord>
            {
                Host("10.0.0.100", true), Host("10.0.0.9", true), Host("10.0.1.1", true),
            }));

            var ips = store.GetInventory().Select(h => h.Ip).ToArray();
            Assert.Equal(new[] { "10.0.0.9", "10.0.0.100", "10.0.1.1" }, ips);
        }

        [Fact]
        public void GetHostHistory_NewestFirst()
        {
            using var store = new ScanHistoryStore(_dbPath);
            long id1 = store.RecordScan(Scan1());
            long id2 = store.RecordScan(Scan2());

            var hist = store.GetHostHistory("10.0.0.2");

            Assert.Equal(2, hist.Count);
            Assert.Equal(id2, hist[0].ScanId);
            Assert.False(hist[0].Alive);
            Assert.Equal(id1, hist[1].ScanId);
            Assert.True(hist[1].Alive);
            Assert.Equal("80/443/", hist[1].Ports);

            Assert.Empty(store.GetHostHistory("10.9.9.9"));
            Assert.Single(store.GetHostHistory("10.0.0.3"));
            Assert.True(store.GetHostHistory("10.0.0.3")[0].HasProhibited);
        }

        [Fact]
        public void GetLastScanStates_ReturnsNullWhenEmpty_ThenLatestScan()
        {
            using var store = new ScanHistoryStore(_dbPath);
            Assert.Null(store.GetLastScanStates());

            store.RecordScan(Scan1());
            store.RecordScan(Scan2());

            var states = store.GetLastScanStates();
            Assert.NotNull(states);
            Assert.Equal(3, states!.Count);
            Assert.True(states["10.0.0.1"].Alive);
            Assert.Equal("22/8080/", states["10.0.0.1"].Ports);
            Assert.False(states["10.0.0.2"].Alive);
            Assert.True(states["10.0.0.3"].HasProhibited);
            Assert.Equal("AA-BB-CC-00-00-03", states["10.0.0.3"].Mac);
        }

        [Fact]
        public void Prune_RemovesOldScansAndTheirHosts()
        {
            using var store = new ScanHistoryStore(_dbPath);
            store.RecordScan(Scan1());
            long id2 = store.RecordScan(Scan2());

            int removed = store.Prune(T1.AddHours(1));

            Assert.Equal(1, removed);
            var scans = store.ListScans();
            Assert.Single(scans);
            Assert.Equal(id2, scans[0].Id);
            // cascade로 scan_hosts도 함께 삭제된다.
            Assert.Single(store.GetHostHistory("10.0.0.2"));
            Assert.Equal(id2, store.GetHostHistory("10.0.0.2")[0].ScanId);
            // 인벤토리는 보존.
            Assert.Equal(3, store.GetInventory().Count);

            Assert.Equal(0, store.Prune(T1.AddHours(1)));
        }

        [Fact]
        public void Reopen_KeepsDataAndDoesNotRerunMigration()
        {
            using (var store = new ScanHistoryStore(_dbPath))
            {
                store.RecordScan(Scan1());
            }

            using (var store = new ScanHistoryStore(_dbPath))
            {
                Assert.Single(store.ListScans());
                Assert.Equal(2, store.GetInventory().Count);
                store.RecordScan(Scan2());
                Assert.Equal(2, store.ListScans().Count);
            }

            using var conn = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = _dbPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
            }.ToString());
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*), MAX(version) FROM schema_version;";
            using var r = cmd.ExecuteReader();
            Assert.True(r.Read());
            Assert.Equal(1, r.GetInt64(0));
            Assert.Equal(1, r.GetInt64(1));
        }

        [Fact]
        public void FromItems_MapsIPInfoFields()
        {
            var items = new List<IPInfo>
            {
                new() { Ip = "10.0.0.1", Alive = true, Macaddr = "AA-BB", Vendor = "V", SystemName = "pc",
                        Ports = "22/", Service = "SSH", RountTime = "2ms", Ttl = 64, HasProhibitedPort = true },
                new() { Ip = "10.0.0.2", Alive = false },
            };

            var rec = ScanRecord.FromItems(items, T1, T2, "sys", true);

            Assert.Equal(2, rec.Hosts.Count);
            var h = rec.Hosts[0];
            Assert.Equal("10.0.0.1", h.Ip);
            Assert.Equal("AA-BB", h.Mac);
            Assert.Equal("pc", h.Name);
            Assert.Equal("2ms", h.Rtt);
            Assert.Equal(64, h.Ttl);
            Assert.True(h.HasProhibited);
            // null 문자열 속성은 ""로 정규화된다.
            Assert.Equal("", rec.Hosts[1].Mac);
            Assert.Equal("", rec.Hosts[1].Ports);
            Assert.True(rec.Scheduled);

            using var store = new ScanHistoryStore(_dbPath);
            store.RecordScan(rec);
            Assert.Equal("", store.GetInventory()[1].LastMac);
        }
    }
}
