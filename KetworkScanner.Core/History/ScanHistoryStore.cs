using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using Microsoft.Data.Sqlite;

namespace KetworkScanner.History
{
    // 스캔 이력을 SQLite(history.db)에 누적 저장한다. CSV는 "마지막 결과" 한 장이지만,
    // 여기엔 모든 스캔과 호스트별 상태가 쌓여 과거 조회·인벤토리·재시작 후 변화 감지 기준에 쓰인다.
    // 연결은 하나만 열고 _gate로 직렬화하므로 어느 스레드에서 호출해도 안전하다.
    public sealed class ScanHistoryStore : IDisposable
    {
        public static string DefaultPath => UserDataPaths.Resolve("history.db");

        private const int CurrentSchemaVersion = 3;

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
            ImportLegacyAnnotations(Path.Combine(dir ?? "", LegacyAnnotationsFileName));
        }

        // 구버전이 IP별 이름/비고를 두던 파일(ip \t name \t description). 이제는 hosts.note/last_name에 산다.
        public const string LegacyAnnotationsFileName = "annotations.ini";

        // annotations.ini가 DB 옆에 남아 있으면 hosts로 1회 옮기고 파일 이름을 *.migrated로 바꾼다.
        // 비고는 hosts.note가 비어 있을 때만, 이름은 last_name이 비어 있을 때만 채운다(사용자가 그 사이 입력한 값 보호). 실패해도 저장소는 연다.
        private void ImportLegacyAnnotations(string path)
        {
            try
            {
                if (!File.Exists(path)) return;
                var entries = ParseLegacyAnnotations(File.ReadAllText(path, System.Text.Encoding.UTF8));
                lock (_gate)
                {
                    using var tx = _conn.BeginTransaction();
                    using var cmd = _conn.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = @"
INSERT INTO hosts(ip, first_seen, last_seen, last_name, note)
VALUES(@ip, @now, @now, @name, @note)
ON CONFLICT(ip) DO UPDATE SET
    note      = CASE WHEN hosts.note = '' THEN excluded.note ELSE hosts.note END,
    last_name = CASE WHEN hosts.last_name = '' THEN excluded.last_name ELSE hosts.last_name END;";
                    var pIp = cmd.Parameters.Add("@ip", SqliteType.Text);
                    var pName = cmd.Parameters.Add("@name", SqliteType.Text);
                    var pNote = cmd.Parameters.Add("@note", SqliteType.Text);
                    cmd.Parameters.AddWithValue("@now", Fmt(DateTimeOffset.UtcNow));
                    foreach (var (ip, name, note) in entries)
                    {
                        pIp.Value = ip;
                        pName.Value = name;
                        pNote.Value = note;
                        cmd.ExecuteNonQuery();
                    }
                    tx.Commit();
                }
                File.Move(path, path + ".migrated", overwrite: true);
                AppLogger.LogInfo("History", $"annotations.ini migrated: {entries.Count} host(s)");
            }
            catch (Exception ex)
            {
                AppLogger.LogWarn("History", "annotations.ini migration failed: " + ex.Message);
            }
        }

        // 탭 구분 "ip \t name \t description". 잘못된 줄은 건너뛰고, 같은 IP는 마지막 줄이 이긴다. 둘 다 빈 항목은 버린다.
        internal static List<(string Ip, string Name, string Description)> ParseLegacyAnnotations(string text)
        {
            var map = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
            foreach (string line in text.Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                string[] token = line.TrimEnd('\r').Split('\t');
                if (token.Length < 3 || !IPAddress.TryParse(token[0].Trim(), out _)) continue;
                string name = token[1].Trim(), desc = token[2].Trim();
                if (name.Length == 0 && desc.Length == 0) continue;
                map[token[0].Trim()] = (name, desc);
            }
            var list = new List<(string, string, string)>(map.Count);
            foreach (var kv in map) list.Add((kv.Key, kv.Value.Item1, kv.Value.Item2));
            return list;
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
                    case 2: MigrateV2(tx); break;
                    case 3: MigrateV3(tx); break;
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

        // v2: 자산 승인/소유자/태그(hosts), 식별·취약점 결과(scan_hosts), 알림 상태(alerts).
        private void MigrateV2(SqliteTransaction tx)
        {
            Exec(@"
ALTER TABLE hosts ADD COLUMN approved     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN approved_at  TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN approved_mac TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN owner        TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN tags         TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN note         TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN last_risk    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_hosts ADD COLUMN sys_descr  TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_hosts ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_hosts ADD COLUMN findings   TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS alerts(
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key              TEXT NOT NULL UNIQUE,
    type             INTEGER NOT NULL,
    ip               TEXT NOT NULL,
    detail           TEXT NOT NULL DEFAULT '',
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    count            INTEGER NOT NULL DEFAULT 1,
    state            INTEGER NOT NULL DEFAULT 0,
    snooze_until     TEXT NOT NULL DEFAULT '',
    last_notified_at TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_alerts_state ON alerts(state);
", tx);
        }

        // v3: 사실(출처·신뢰도) JSON과 OS 버전/모델/스위치 포트.
        private void MigrateV3(SqliteTransaction tx)
        {
            Exec(@"
ALTER TABLE scan_hosts ADD COLUMN facts       TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_hosts ADD COLUMN os_version  TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_hosts ADD COLUMN model       TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_hosts ADD COLUMN switch_port TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN last_model       TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN last_os          TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN last_switch_port TEXT NOT NULL DEFAULT '';
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
INSERT OR REPLACE INTO scan_hosts(scan_id, ip, alive, mac, vendor, name, ports, service, rtt, ttl, has_prohibited, sys_descr, risk_score, findings, facts, os_version, model, switch_port)
VALUES(@scan, @ip, @alive, @mac, @vendor, @name, @ports, @service, @rtt, @ttl, @prohibited, @sysdescr, @risk, @findings, @facts, @osver, @model, @swport);";
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
                    var pSysDescr = hostCmd.Parameters.Add("@sysdescr", SqliteType.Text);
                    var pRisk = hostCmd.Parameters.Add("@risk", SqliteType.Integer);
                    var pFindings = hostCmd.Parameters.Add("@findings", SqliteType.Text);
                    var pFacts = hostCmd.Parameters.Add("@facts", SqliteType.Text);
                    var pOsVer = hostCmd.Parameters.Add("@osver", SqliteType.Text);
                    var pModel = hostCmd.Parameters.Add("@model", SqliteType.Text);
                    var pSwPort = hostCmd.Parameters.Add("@swport", SqliteType.Text);
                    hostCmd.Parameters.AddWithValue("@scan", scanId);

                    invCmd.Transaction = tx;
                    // 인벤토리 upsert. first_seen은 최초 1회만, last_alive_at은 살아있을 때만 갱신.
                    // MAC/제조사/이름은 이번 스캔에서 비어 있으면(응답 없음 등) 마지막으로 알던 값을 유지하고,
                    // 포트는 살아있을 때의 값만 반영한다.
                    invCmd.CommandText = @"
INSERT INTO hosts(ip, first_seen, last_seen, last_alive_at, last_mac, last_vendor, last_name, last_ports, last_alive, seen_count, last_risk, last_model, last_os, last_switch_port)
VALUES(@ip, @now, @now, CASE WHEN @alive = 1 THEN @now ELSE '' END, @mac, @vendor, @name, @ports, @alive, 1, @risk, @model, @osver, @swport)
ON CONFLICT(ip) DO UPDATE SET
    last_risk     = CASE WHEN excluded.last_alive = 1 THEN excluded.last_risk ELSE hosts.last_risk END,
    last_model    = CASE WHEN excluded.last_model <> '' THEN excluded.last_model ELSE hosts.last_model END,
    last_os       = CASE WHEN excluded.last_os <> '' THEN excluded.last_os ELSE hosts.last_os END,
    last_switch_port = CASE WHEN excluded.last_switch_port <> '' THEN excluded.last_switch_port ELSE hosts.last_switch_port END,
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
                    var iRisk = invCmd.Parameters.Add("@risk", SqliteType.Integer);
                    var iModel = invCmd.Parameters.Add("@model", SqliteType.Text);
                    var iOsVer = invCmd.Parameters.Add("@osver", SqliteType.Text);
                    var iSwPort = invCmd.Parameters.Add("@swport", SqliteType.Text);
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
                        pSysDescr.Value = h.SysDescr ?? "";
                        pRisk.Value = h.RiskScore;
                        pFindings.Value = h.FindingsJson ?? "";
                        pFacts.Value = h.FactsJson ?? "";
                        pOsVer.Value = h.OsVersion ?? "";
                        pModel.Value = h.Model ?? "";
                        pSwPort.Value = h.SwitchPort ?? "";
                        hostCmd.ExecuteNonQuery();

                        iIp.Value = h.Ip;
                        iAlive.Value = h.Alive ? 1 : 0;
                        iMac.Value = h.Mac ?? "";
                        iVendor.Value = h.Vendor ?? "";
                        iName.Value = h.Name ?? "";
                        iPorts.Value = h.Ports ?? "";
                        iRisk.Value = h.RiskScore;
                        iModel.Value = h.Model ?? "";
                        iOsVer.Value = h.OsVersion ?? "";
                        iSwPort.Value = h.SwitchPort ?? "";
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
SELECT h.scan_id, s.started_at, h.alive, h.mac, h.ports, h.service, h.has_prohibited, h.risk_score
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
                        r.GetString(3), r.GetString(4), r.GetString(5), r.GetInt64(6) != 0, r.GetInt32(7)));
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
SELECT ip, first_seen, last_seen, last_alive_at, last_mac, last_vendor, last_name, last_ports, last_alive, seen_count,
       approved, approved_mac, owner, tags, note, last_risk, last_model, last_os, last_switch_port
FROM hosts;";
                    using var r = cmd.ExecuteReader();
                    while (r.Read())
                    {
                        string lastAliveAt = r.GetString(3);
                        list.Add(new HostInventoryEntry(
                            r.GetString(0), Parse(r.GetString(1)), Parse(r.GetString(2)),
                            lastAliveAt.Length == 0 ? null : Parse(lastAliveAt),
                            r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7),
                            r.GetInt64(8) != 0, r.GetInt32(9),
                            r.GetInt64(10) != 0, r.GetString(11), r.GetString(12), r.GetString(13), r.GetString(14), r.GetInt32(15),
                            r.GetString(16), r.GetString(17), r.GetString(18)));
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

        // 가장 최근 스캔에서 이 IP에 대해 기록된 사실 JSON(없으면 ""). 여러 시점 관측을 합칠 때 쓴다.
        public string GetLastFactsJson(string ip)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT facts FROM scan_hosts WHERE ip = @ip AND facts <> '' ORDER BY scan_id DESC LIMIT 1;";
                cmd.Parameters.AddWithValue("@ip", ip);
                object? v = cmd.ExecuteScalar();
                return v is string s ? s : "";
            }
        }

        // ---- 자산 승인 / 메타 ----

        // 승인된 자산 목록(IP → 승인 MAC/소유자). 미승인 장비 판정의 기준.
        public IReadOnlyDictionary<string, ApprovedHost> GetApprovedHosts()
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var map = new Dictionary<string, ApprovedHost>();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT ip, approved_mac, owner FROM hosts WHERE approved = 1;";
                using var r = cmd.ExecuteReader();
                while (r.Read()) map[r.GetString(0)] = new ApprovedHost(r.GetString(0), r.GetString(1), r.GetString(2));
                return map;
            }
        }

        // 승인/승인 해제. 승인 시 현재 알려진 MAC을 승인 MAC으로 고정한다(인벤토리에 없는 IP는 행을 만든다).
        public int SetApproved(IEnumerable<string> ips, bool approved, DateTimeOffset now)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int n = 0;
                using var tx = _conn.BeginTransaction();
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = approved
                    ? @"INSERT INTO hosts(ip, first_seen, last_seen, approved, approved_at, approved_mac)
                        VALUES(@ip, @now, @now, 1, @now, '')
                        ON CONFLICT(ip) DO UPDATE SET approved = 1, approved_at = @now, approved_mac = hosts.last_mac;"
                    : "UPDATE hosts SET approved = 0, approved_at = '', approved_mac = '' WHERE ip = @ip;";
                var pIp = cmd.Parameters.Add("@ip", SqliteType.Text);
                cmd.Parameters.AddWithValue("@now", Fmt(now));
                foreach (string ip in ips)
                {
                    if (string.IsNullOrWhiteSpace(ip)) continue;
                    pIp.Value = ip.Trim();
                    n += cmd.ExecuteNonQuery();
                }
                tx.Commit();
                return n;
            }
        }

        // 소유자/태그/메모. null인 항목은 바꾸지 않는다.
        public bool SetHostMeta(string ip, string? owner, string? tags, string? note)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            lock (_gate)
            {
                ThrowIfDisposed();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = @"
INSERT INTO hosts(ip, first_seen, last_seen, owner, tags, note)
VALUES(@ip, @now, @now, COALESCE(@owner, ''), COALESCE(@tags, ''), COALESCE(@note, ''))
ON CONFLICT(ip) DO UPDATE SET
    owner = COALESCE(@owner, hosts.owner),
    tags  = COALESCE(@tags,  hosts.tags),
    note  = COALESCE(@note,  hosts.note);";
                cmd.Parameters.AddWithValue("@ip", ip.Trim());
                cmd.Parameters.AddWithValue("@now", Fmt(DateTimeOffset.UtcNow));
                cmd.Parameters.AddWithValue("@owner", (object?)owner ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@tags", (object?)tags ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@note", (object?)note ?? DBNull.Value);
                return cmd.ExecuteNonQuery() > 0;
            }
        }

        // 인벤토리의 비어 있지 않은 비고(IP → note). 엔진이 스캔/CSV 불러오기 때 Description을 채우는 데 쓴다.
        public IReadOnlyDictionary<string, string> GetHostNotes()
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var map = new Dictionary<string, string>(StringComparer.Ordinal);
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "SELECT ip, note FROM hosts WHERE note <> '';";
                using var r = cmd.ExecuteReader();
                while (r.Read()) map[r.GetString(0)] = r.GetString(1);
                return map;
            }
        }

        // 여러 호스트의 비고를 한 트랜잭션으로 저장한다(행이 없으면 만든다). 반환값은 처리한 호스트 수.
        public int SetHostNotes(IEnumerable<KeyValuePair<string, string>> notes)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                int n = 0;
                using var tx = _conn.BeginTransaction();
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = @"
INSERT INTO hosts(ip, first_seen, last_seen, note) VALUES(@ip, @now, @now, @note)
ON CONFLICT(ip) DO UPDATE SET note = excluded.note;";
                var pIp = cmd.Parameters.Add("@ip", SqliteType.Text);
                var pNote = cmd.Parameters.Add("@note", SqliteType.Text);
                cmd.Parameters.AddWithValue("@now", Fmt(DateTimeOffset.UtcNow));
                foreach (var kv in notes)
                {
                    if (string.IsNullOrWhiteSpace(kv.Key)) continue;
                    pIp.Value = kv.Key.Trim();
                    pNote.Value = kv.Value ?? "";
                    n += cmd.ExecuteNonQuery();
                }
                tx.Commit();
                return n;
            }
        }

        // 인벤토리에서 한 호스트를 지운다(스캔 이력은 남는다).
        public bool DeleteHost(string ip)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "DELETE FROM hosts WHERE ip = @ip;";
                cmd.Parameters.AddWithValue("@ip", ip);
                return cmd.ExecuteNonQuery() > 0;
            }
        }

        // ---- 알림 ----

        // 같은 key의 알림이 있으면 횟수/마지막 시각을 올리고(해결됨이었으면 다시 open), 없으면 새로 만든다. 반환값은 현재 행.
        public AlertRecord UpsertAlert(string key, ScanChangeType type, string ip, string detail, DateTimeOffset now)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.CommandText = @"
INSERT INTO alerts(key, type, ip, detail, first_seen, last_seen, count, state)
VALUES(@key, @type, @ip, @detail, @now, @now, 1, 0)
ON CONFLICT(key) DO UPDATE SET
    last_seen = @now,
    detail    = excluded.detail,
    count     = alerts.count + 1,
    state     = CASE WHEN alerts.state = 3 THEN 0
                     WHEN alerts.state = 2 AND alerts.snooze_until <> '' AND alerts.snooze_until < @now THEN 0
                     ELSE alerts.state END;";
                    cmd.Parameters.AddWithValue("@key", key);
                    cmd.Parameters.AddWithValue("@type", (int)type);
                    cmd.Parameters.AddWithValue("@ip", ip);
                    cmd.Parameters.AddWithValue("@detail", detail ?? "");
                    cmd.Parameters.AddWithValue("@now", Fmt(now));
                    cmd.ExecuteNonQuery();
                }
                return GetAlertByKey(key)!;
            }
        }

        public AlertRecord? GetAlertByKey(string key)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = AlertSelect + " WHERE key = @key;";
                cmd.Parameters.AddWithValue("@key", key);
                using var r = cmd.ExecuteReader();
                return r.Read() ? ReadAlert(r) : null;
            }
        }

        public IReadOnlyList<AlertRecord> ListAlerts(bool includeResolved = false, int limit = 500)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var list = new List<AlertRecord>();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = AlertSelect + (includeResolved ? "" : " WHERE state <> 3") + " ORDER BY last_seen DESC, id DESC LIMIT @limit;";
                cmd.Parameters.AddWithValue("@limit", limit);
                using var r = cmd.ExecuteReader();
                while (r.Read()) list.Add(ReadAlert(r));
                return list;
            }
        }

        public bool SetAlertState(long id, AlertState state, DateTimeOffset? snoozeUntil = null, string? note = null)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "UPDATE alerts SET state = @state, snooze_until = @until, note = COALESCE(@note, note) WHERE id = @id;";
                cmd.Parameters.AddWithValue("@state", (int)state);
                cmd.Parameters.AddWithValue("@until", snoozeUntil.HasValue ? Fmt(snoozeUntil.Value) : "");
                cmd.Parameters.AddWithValue("@note", (object?)note ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@id", id);
                return cmd.ExecuteNonQuery() > 0;
            }
        }

        public void MarkAlertsNotified(IEnumerable<long> ids, DateTimeOffset now)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                using var tx = _conn.BeginTransaction();
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "UPDATE alerts SET last_notified_at = @now WHERE id = @id;";
                var pId = cmd.Parameters.Add("@id", SqliteType.Integer);
                cmd.Parameters.AddWithValue("@now", Fmt(now));
                foreach (long id in ids) { pId.Value = id; cmd.ExecuteNonQuery(); }
                tx.Commit();
            }
        }

        // 이번 스캔에서 더 이상 관찰되지 않는 열린 알림을 '해결됨'으로 닫는다(key 목록은 이번 스캔의 활성 key).
        public int ResolveAlertsNotIn(IReadOnlyCollection<string> activeKeys, IEnumerable<ScanChangeType> resolvableTypes)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                var types = new List<int>();
                foreach (var t in resolvableTypes) types.Add((int)t);
                if (types.Count == 0) return 0;

                var active = new HashSet<string>(activeKeys);
                var toResolve = new List<long>();
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.CommandText = $"SELECT id, key FROM alerts WHERE state <> 3 AND type IN ({string.Join(",", types)});";
                    using var r = cmd.ExecuteReader();
                    while (r.Read()) if (!active.Contains(r.GetString(1))) toResolve.Add(r.GetInt64(0));
                }
                if (toResolve.Count == 0) return 0;

                using var tx = _conn.BeginTransaction();
                using (var cmd = _conn.CreateCommand())
                {
                    cmd.Transaction = tx;
                    cmd.CommandText = "UPDATE alerts SET state = 3 WHERE id = @id;";
                    var pId = cmd.Parameters.Add("@id", SqliteType.Integer);
                    foreach (long id in toResolve) { pId.Value = id; cmd.ExecuteNonQuery(); }
                }
                tx.Commit();
                return toResolve.Count;
            }
        }

        private const string AlertSelect = "SELECT id, key, type, ip, detail, first_seen, last_seen, count, state, snooze_until, last_notified_at, note FROM alerts";

        private static AlertRecord ReadAlert(SqliteDataReader r)
        {
            string snooze = r.GetString(9), notified = r.GetString(10);
            return new AlertRecord(r.GetInt64(0), r.GetString(1), (ScanChangeType)r.GetInt32(2), r.GetString(3), r.GetString(4),
                Parse(r.GetString(5)), Parse(r.GetString(6)), r.GetInt32(7), (AlertState)r.GetInt32(8),
                snooze.Length == 0 ? null : Parse(snooze), notified.Length == 0 ? null : Parse(notified), r.GetString(11));
        }

        // ---- 유지보수 ----

        // 온라인 백업(VACUUM INTO): 열려 있는 상태에서도 일관된 복사본을 만든다.
        public void BackupTo(string path)
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                if (File.Exists(path)) File.Delete(path);
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = "VACUUM INTO @path;";
                cmd.Parameters.AddWithValue("@path", path);
                cmd.ExecuteNonQuery();
            }
        }

        public long FileSizeBytes
        {
            get
            {
                try { return new FileInfo(_conn.DataSource).Length; } catch { return 0; }
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
