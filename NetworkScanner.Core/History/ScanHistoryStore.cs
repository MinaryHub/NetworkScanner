using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using Microsoft.Data.Sqlite;

namespace NetworkScanner.History
{
    // 스캔 이력을 SQLite(history.db)에 누적 저장한다. CSV는 "마지막 결과" 한 장이지만,
    // 여기엔 모든 스캔과 호스트별 상태가 쌓여 과거 조회·인벤토리·재시작 후 변화 감지 기준에 쓰인다.
    // 연결은 하나만 열고 _gate로 직렬화하므로 어느 스레드에서 호출해도 안전하다.
    public sealed class ScanHistoryStore : IDisposable
    {
        public static string DefaultPath => UserDataPaths.Resolve("history.db");

        private const int CurrentSchemaVersion = 1;

        private readonly object _gate = new();
        private readonly SqliteConnection _conn;
        private bool _disposed;

        public ScanHistoryStore(string dbPath)
        {
            if (string.IsNullOrWhiteSpace(dbPath)) throw new ArgumentException("dbPath is required", nameof(dbPath));

            string? dir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            // Pooling=false: Dispose 직후 파일 핸들이 닫혀 삭제/이동(테스트, 정리)이 바로 가능하다.
            var cs = new SqliteConnectionStringBuilder
            {
                DataSource = dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            };
            _conn = new SqliteConnection(cs.ToString());
            _conn.Open();

            Exec("PRAGMA journal_mode=WAL;");
            Exec("PRAGMA busy_timeout=5000;");
            Exec("PRAGMA foreign_keys=ON;");

            Migrate();
        }

        // ---- 스키마 ----

        // schema_version에 적용된 버전을 기록하고, 빠진 버전의 마이그레이션만 순서대로 실행한다.
        private void Migrate()
        {
            Exec("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);");

            int applied;
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_version;";
                applied = Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
            }

            for (int v = applied + 1; v <= CurrentSchemaVersion; v++)
            {
                using var tx = _conn.BeginTransaction();
                switch (v)
                {
                    case 1: MigrateV1(tx); break;
                }
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.Transaction = tx;
                    cmd.CommandText = "INSERT INTO schema_version(version) VALUES(@v);";
                    cmd.Parameters.AddWithValue("@v", v);
                    cmd.ExecuteNonQuery();
                }
                tx.Commit();
            }
        }

        private void MigrateV1(SqliteTransaction tx)
        {
            Exec(@"
CREATE TABLE IF NOT EXISTS scans(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    system_name TEXT NOT NULL DEFAULT '',
    total       INTEGER NOT NULL DEFAULT 0,
    alive       INTEGER NOT NULL DEFAULT 0,
    prohibited  INTEGER NOT NULL DEFAULT 0,
    scheduled   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_hosts(
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL,
    alive          INTEGER NOT NULL DEFAULT 0,
    mac            TEXT NOT NULL DEFAULT '',
    vendor         TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    ports          TEXT NOT NULL DEFAULT '',
    service        TEXT NOT NULL DEFAULT '',
    rtt            TEXT NOT NULL DEFAULT '',
    ttl            INTEGER NOT NULL DEFAULT 0,
    has_prohibited INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(scan_id, ip)
);
CREATE TABLE IF NOT EXISTS hosts(
    ip            TEXT PRIMARY KEY,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    last_alive_at TEXT NOT NULL DEFAULT '',
    last_mac      TEXT NOT NULL DEFAULT '',
    last_vendor   TEXT NOT NULL DEFAULT '',
    last_name     TEXT NOT NULL DEFAULT '',
    last_ports    TEXT NOT NULL DEFAULT '',
    last_alive    INTEGER NOT NULL DEFAULT 0,
    seen_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scan_hosts_ip ON scan_hosts(ip);
CREATE INDEX IF NOT EXISTS ix_scans_started_at ON scans(started_at);
", tx);
        }

        // ---- 쓰기 ----

        // 스캔 1건과 호스트 결과를 저장하고 hosts 인벤토리를 갱신한다. 반환값은 scans.id.
        public long RecordScan(ScanRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));

            lock (_gate)
            {
                ThrowIfDisposed();
                using var tx = _conn.BeginTransaction();

                int total = record.Hosts.Count, alive = 0, prohibited = 0;
                foreach (var h in record.Hosts)
                {
                    if (h.Alive) alive++;
                    if (h.HasProhibited) prohibited++;
                }

                string startedAt = Fmt(record.StartedAt);
                string finishedAt = Fmt(record.FinishedAt);

                long scanId;
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
INSERT INTO scans(started_at, finished_at, system_name, total, alive, prohibited, scheduled)
VALUES(@started, @finished, @name, @total, @alive, @prohibited, @scheduled);
SELECT last_insert_rowid();";
                    cmd.Parameters.AddWithValue("@started", startedAt);
                    cmd.Parameters.AddWithValue("@finished", finishedAt);
                    cmd.Parameters.AddWithValue("@name", record.SystemName ?? "");
                    cmd.Parameters.AddWithValue("@total", total);
                    cmd.Parameters.AddWithValue("@alive", alive);
                    cmd.Parameters.AddWithValue("@prohibited", prohibited);
                    cmd.Parameters.AddWithValue("@scheduled", record.Scheduled ? 1 : 0);
                    scanId = (long)cmd.ExecuteScalar()!;
                }

                using (var hostCmd = _conn.CreateCommand())
                using (var invCmd = _conn.CreateCommand())
                {
                    hostCmd.Transaction = tx;
                    // 같은 IP가 두 번 들어와도(중복 범위 등) 마지막 값으로 덮어쓴다.
                    hostCmd.CommandText = @"
INSERT OR REPLACE INTO scan_hosts(scan_id, ip, alive, mac, vendor, name, ports, service, rtt, ttl, has_prohibited)
VALUES(@scan, @ip, @alive, @mac, @vendor, @name, @ports, @service, @rtt, @ttl, @prohibited);";
                    var pIp = hostCmd.Parameters.Add("@ip", SqliteType.Text);
                    var pAlive = hostCmd.Parameters.Add("@alive", SqliteType.Integer);
                    var pMac = hostCmd.Parameters.Add("@mac", SqliteType.Text);
                    var pVendor = hostCmd.Parameters.Add("@vendor", SqliteType.Text);
                    var pName = hostCmd.Parameters.Add("@name", SqliteType.Text);
                    var pPorts = hostCmd.Parameters.Add("@ports", SqliteType.Text);
                    var pService = hostCmd.Parameters.Add("@service", SqliteType.Text);
                    var pRtt = hostCmd.Parameters.Add("@rtt", SqliteType.Text);
                    var pTtl = hostCmd.Parameters.Add("@ttl", SqliteType.Integer);
                    var pProhibited = hostCmd.Parameters.Add("@prohibited", SqliteType.Integer);
                    hostCmd.Parameters.AddWithValue("@scan", scanId);

                    invCmd.Transaction = tx;
                    // 인벤토리 upsert. first_seen은 최초 1회만, last_alive_at은 살아있을 때만 갱신.
                    // MAC/제조사/이름은 이번 스캔에서 비어 있으면(응답 없음 등) 마지막으로 알던 값을 유지하고,
                    // 포트는 살아있을 때의 값만 반영한다.
                    invCmd.CommandText = @"
INSERT INTO hosts(ip, first_seen, last_seen, last_alive_at, last_mac, last_vendor, last_name, last_ports, last_alive, seen_count)
VALUES(@ip, @now, @now, CASE WHEN @alive = 1 THEN @now ELSE '' END, @mac, @vendor, @name, @ports, @alive, 1)
ON CONFLICT(ip) DO UPDATE SET
    last_seen     = excluded.last_seen,
    last_alive_at = CASE WHEN excluded.last_alive = 1 THEN excluded.last_seen ELSE hosts.last_alive_at END,
    last_mac      = CASE WHEN excluded.last_mac    <> '' THEN excluded.last_mac    ELSE hosts.last_mac    END,
    last_vendor   = CASE WHEN excluded.last_vendor <> '' THEN excluded.last_vendor ELSE hosts.last_vendor END,
    last_name     = CASE WHEN excluded.last_name   <> '' THEN excluded.last_name   ELSE hosts.last_name   END,
    last_ports    = CASE WHEN excluded.last_alive = 1 THEN excluded.last_ports ELSE hosts.last_ports END,
    last_alive    = excluded.last_alive,
    seen_count    = hosts.seen_count + 1;";
                    var iIp = invCmd.Parameters.Add("@ip", SqliteType.Text);
                    var iAlive = invCmd.Parameters.Add("@alive", SqliteType.Integer);
                    var iMac = invCmd.Parameters.Add("@mac", SqliteType.Text);
                    var iVendor = invCmd.Parameters.Add("@vendor", SqliteType.Text);
                    var iName = invCmd.Parameters.Add("@name", SqliteType.Text);
                    var iPorts = invCmd.Parameters.Add("@ports", SqliteType.Text);
                    invCmd.Parameters.AddWithValue("@now", startedAt);

                    foreach (var h in record.Hosts)
                    {
                        if (string.IsNullOrEmpty(h.Ip)) continue;

                        pIp.Value = h.Ip;
                        pAlive.Value = h.Alive ? 1 : 0;
                        pMac.Value = h.Mac ?? "";
                        pVendor.Value = h.Vendor ?? "";
                        pName.Value = h.Name ?? "";
                        pPorts.Value = h.Ports ?? "";
                        pService.Value = h.Service ?? "";
                        pRtt.Value = h.Rtt ?? "";
                        pTtl.Value = h.Ttl;
                        pProhibited.Value = h.HasProhibited ? 1 : 0;
                        hostCmd.ExecuteNonQuery();

                        iIp.Value = h.Ip;
                        iAlive.Value = h.Alive ? 1 : 0;
                        iMac.Value = h.Mac ?? "";
                        iVendor.Value = h.Vendor ?? "";
                        iName.Value = h.Name ?? "";
                        iPorts.Value = h.Ports ?? "";
                        invCmd.ExecuteNonQuery();
                    }
                }

                tx.Commit();
                return scanId;
            }
        }

        // 지정 시각보다 먼저 시작된 스캔을 삭제한다(scan_hosts는 cascade). 반환값은 삭제된 스캔 수.
        public int Prune(DateTimeOffset olderThan)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int removed;
                using (var tx = _conn.BeginTransaction())
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.Transaction = tx;
                    // "o" UTC 문자열은 길이·형식이 같아 문자열 비교가 시간순과 일치한다.
                    cmd.CommandText = "DELETE FROM scans WHERE started_at < @cutoff;";
                    cmd.Parameters.AddWithValue("@cutoff", Fmt(olderThan));
                    removed = cmd.ExecuteNonQuery();
                    tx.Commit();
                }
                // 삭제로 비워진 WAL을 정리해 파일 크기를 줄인다.
                Exec("PRAGMA wal_checkpoint(TRUNCATE);");
                return removed;
            }
        }

        // ---- 읽기 ----

        // 최근 스캔부터 limit개.
        public IReadOnlyList<ScanSummary> ListScans(int limit = 50)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var list = new List<ScanSummary>();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = @"
SELECT id, started_at, finished_at, system_name, total, alive, prohibited, scheduled
FROM scans ORDER BY started_at DESC, id DESC LIMIT @limit;";
                cmd.Parameters.AddWithValue("@limit", limit);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    list.Add(new ScanSummary(
                        r.GetInt64(0), Parse(r.GetString(1)), Parse(r.GetString(2)), r.GetString(3),
                        r.GetInt32(4), r.GetInt32(5), r.GetInt32(6), r.GetInt64(7) != 0));
                }
                return list;
            }
        }

        // 특정 IP의 스캔별 상태를 최근 순으로 limit개.
        public IReadOnlyList<HostHistoryEntry> GetHostHistory(string ip, int limit = 100)
        {
            if (string.IsNullOrEmpty(ip)) return Array.Empty<HostHistoryEntry>();

            lock (_gate)
            {
                ThrowIfDisposed();
                var list = new List<HostHistoryEntry>();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = @"
SELECT h.scan_id, s.started_at, h.alive, h.mac, h.ports, h.service, h.has_prohibited
FROM scan_hosts h JOIN scans s ON s.id = h.scan_id
WHERE h.ip = @ip
ORDER BY s.started_at DESC, s.id DESC LIMIT @limit;";
                cmd.Parameters.AddWithValue("@ip", ip);
                cmd.Parameters.AddWithValue("@limit", limit);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    list.Add(new HostHistoryEntry(
                        r.GetInt64(0), Parse(r.GetString(1)), r.GetInt64(2) != 0,
                        r.GetString(3), r.GetString(4), r.GetString(5), r.GetInt64(6) != 0));
                }
                return list;
            }
        }

        // 지금까지 본 모든 호스트의 인벤토리. IP를 uint32로 보고 오름차순 정렬(문자열 정렬 오류 방지).
        public IReadOnlyList<HostInventoryEntry> GetInventory()
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var list = new List<HostInventoryEntry>();
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.CommandText = @"
SELECT ip, first_seen, last_seen, last_alive_at, last_mac, last_vendor, last_name, last_ports, last_alive, seen_count
FROM hosts;";
                    using var r = cmd.ExecuteReader();
                    while (r.Read())
                    {
                        string lastAliveAt = r.GetString(3);
                        list.Add(new HostInventoryEntry(
                            r.GetString(0), Parse(r.GetString(1)), Parse(r.GetString(2)),
                            lastAliveAt.Length == 0 ? null : Parse(lastAliveAt),
                            r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7),
                            r.GetInt64(8) != 0, r.GetInt32(9)));
                    }
                }

                list.Sort((a, b) =>
                {
                    int c = IpKey(a.Ip).CompareTo(IpKey(b.Ip));
                    return c != 0 ? c : string.CompareOrdinal(a.Ip, b.Ip);
                });
                return list;
            }
        }

        // 가장 최근 스캔의 IP별 상태. 스캔 기록이 없으면 null.
        // 엔진이 재시작 후 변화 감지(ScanDiff)의 기준(baseline)으로 쓴다.
        public IReadOnlyDictionary<string, HostState>? GetLastScanStates()
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                long scanId;
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT 1;";
                    object? v = cmd.ExecuteScalar();
                    if (v == null || v is DBNull) return null;
                    scanId = (long)v;
                }

                var states = new Dictionary<string, HostState>();
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT ip, alive, mac, ports, has_prohibited FROM scan_hosts WHERE scan_id = @scan;";
                    cmd.Parameters.AddWithValue("@scan", scanId);
                    using var r = cmd.ExecuteReader();
                    while (r.Read())
                        states[r.GetString(0)] = new HostState(r.GetInt64(1) != 0, r.GetString(2), r.GetString(3), r.GetInt64(4) != 0);
                }
                return states;
            }
        }

        // ---- 내부 ----

        private void Exec(string sql, SqliteTransaction? tx = null)
        {
            using var cmd = _conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        // 시각은 항상 UTC ISO-8601("o") 문자열로 저장해 정렬·비교가 문자열로도 정확하도록 한다.
        private static string Fmt(DateTimeOffset t) => t.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

        private static DateTimeOffset Parse(string s)
            => DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var t)
                ? t : DateTimeOffset.MinValue;

        private static uint IpKey(string ip)
            => IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? IPRangeUtil.ToUInt32(addr) : uint.MaxValue;

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ScanHistoryStore));
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed) return;
                _disposed = true;
                _conn.Dispose();
            }
        }
    }
}
