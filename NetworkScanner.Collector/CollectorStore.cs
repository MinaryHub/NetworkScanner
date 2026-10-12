using System.Globalization;
using Microsoft.Data.Sqlite;

namespace NetworkScanner.Collector;

public sealed record UploadRow(long Id, string Site, string FileName, string RelPath, string Kind, long Size, string ReceivedAt);

public sealed record ScanSummary(long Id, long UploadId, string Site, string SystemName, string ReceivedAt, int Total, int Alive, int Risky, int HighRisk);

public sealed record HostRow(
    string Ip, bool Alive, string Name, string Mac, string Vendor, string Ports, int RiskScore, bool HasProhibited,
    string OsHint, string OsVersion, string Model, string DeviceHint, string Service, string SwitchPort, string Ipv6, bool Approved, string Owner)
{
    // 표시용 OS: 핑거프린트로 확인한 상세 버전이 있으면 그것, 없으면 힌트.
    public string Os => OsVersion.Length > 0 ? OsVersion : OsHint;
}

public sealed record SiteSummary(string Site, string? LastUploadAt, int UploadCount, ScanSummary? LastScan, long? LatestReportId, string? LatestReportKind);

// <DataDir>/collector.db 색인. 쓰기는 한 번에 하나만(SQLite 단일 작성자), 읽기는 WAL 덕분에 동시에 가능하다.
public sealed class CollectorStore
{
    // 스키마 버전(PRAGMA user_version). 2: scan_hosts에 OS/모델/서비스/스위치 포트/IPv6/승인/담당자 열 추가.
    private const int SchemaVersion = 2;
    private static readonly string[] UploadKinds = { "csv", "html", "pdf", "json" };

    private readonly string _connectionString;
    private readonly string _dataDir;
    private readonly object _writeLock = new();
    private readonly int _scansPerSite;

    public CollectorStore(CollectorOptions options)
    {
        Directory.CreateDirectory(options.DataDir);
        _dataDir = options.DataDir;
        DbPath = Path.Combine(options.DataDir, "collector.db");
        _scansPerSite = Math.Max(1, options.ScansPerSite);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 10,
        }.ToString();
        EnsureSchema();
    }

    public string DbPath { get; }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        return c;
    }

    private void EnsureSchema()
    {
        using SqliteConnection c = Open();
        using (SqliteCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    rel_path TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    received_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_uploads_site ON uploads(site, id);
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER NOT NULL,
                    site TEXT NOT NULL,
                    system_name TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    total INTEGER NOT NULL,
                    alive INTEGER NOT NULL,
                    risky INTEGER NOT NULL,
                    high_risk INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_scans_site ON scans(site, id);
                CREATE TABLE IF NOT EXISTS scan_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    alive INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    has_prohibited INTEGER NOT NULL,
                    os_hint TEXT NOT NULL DEFAULT '',
                    os_version TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    device_hint TEXT NOT NULL DEFAULT '',
                    service TEXT NOT NULL DEFAULT '',
                    switch_port TEXT NOT NULL DEFAULT '',
                    ipv6 TEXT NOT NULL DEFAULT '',
                    approved INTEGER NOT NULL DEFAULT 0,
                    owner TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS ix_scan_hosts_scan ON scan_hosts(scan_id);
                """;
            cmd.ExecuteNonQuery();
        }
        Migrate(c);
    }

    // 이전 버전(v1)의 scan_hosts에 없는 열을 추가한다. 열 존재 여부로 판단하므로 몇 번 실행해도 안전하다.
    private static void Migrate(SqliteConnection c)
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (SqliteCommand info = c.CreateCommand())
        {
            info.CommandText = "PRAGMA table_info(scan_hosts)";
            using SqliteDataReader r = info.ExecuteReader();
            while (r.Read()) existing.Add(r.GetString(1));
        }

        (string Name, string Definition)[] added =
        {
            ("os_hint", "TEXT NOT NULL DEFAULT ''"),
            ("os_version", "TEXT NOT NULL DEFAULT ''"),
            ("model", "TEXT NOT NULL DEFAULT ''"),
            ("device_hint", "TEXT NOT NULL DEFAULT ''"),
            ("service", "TEXT NOT NULL DEFAULT ''"),
            ("switch_port", "TEXT NOT NULL DEFAULT ''"),
            ("ipv6", "TEXT NOT NULL DEFAULT ''"),
            ("approved", "INTEGER NOT NULL DEFAULT 0"),
            ("owner", "TEXT NOT NULL DEFAULT ''"),
        };
        foreach ((string name, string def) in added)
        {
            if (existing.Contains(name)) continue;
            using SqliteCommand alter = c.CreateCommand();
            alter.CommandText = $"ALTER TABLE scan_hosts ADD COLUMN {name} {def}";
            alter.ExecuteNonQuery();
        }

        using SqliteCommand ver = c.CreateCommand();
        ver.CommandText = "PRAGMA user_version = " + SchemaVersion.ToString(CultureInfo.InvariantCulture);
        ver.ExecuteNonQuery();
    }

    public int UserVersion
    {
        get
        {
            using SqliteConnection c = Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = "PRAGMA user_version";
            return Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
        }
    }

    public static string Stamp(DateTime utc) => utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public long AddUpload(string site, string fileName, string relPath, string kind, long size, DateTime receivedAtUtc)
    {
        lock (_writeLock)
        {
            using SqliteConnection c = Open();
            using SqliteCommand cmd = c.CreateCommand();
            cmd.CommandText = """
                INSERT INTO uploads(site, file_name, rel_path, kind, size, received_at)
                VALUES (@site, @name, @rel, @kind, @size, @at);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("@site", site);
            cmd.Parameters.AddWithValue("@name", fileName);
            cmd.Parameters.AddWithValue("@rel", relPath);
            cmd.Parameters.AddWithValue("@kind", kind);
            cmd.Parameters.AddWithValue("@size", size);
            cmd.Parameters.AddWithValue("@at", Stamp(receivedAtUtc));
            return (long)cmd.ExecuteScalar()!;
        }
    }

    // 스캔 요약 + 호스트 행을 한 트랜잭션으로 넣는다. 보관 한도 정리는 PruneSite가 맡는다.
    public long AddScan(long uploadId, string site, string systemName, DateTime receivedAtUtc, ParsedScan scan)
    {
        lock (_writeLock)
        {
            using SqliteConnection c = Open();
            using SqliteTransaction tx = c.BeginTransaction();

            long scanId;
            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO scans(upload_id, site, system_name, received_at, total, alive, risky, high_risk)
                    VALUES (@up, @site, @sys, @at, @total, @alive, @risky, @high);
                    SELECT last_insert_rowid();
                    """;
                cmd.Parameters.AddWithValue("@up", uploadId);
                cmd.Parameters.AddWithValue("@site", site);
                cmd.Parameters.AddWithValue("@sys", systemName);
                cmd.Parameters.AddWithValue("@at", Stamp(receivedAtUtc));
                cmd.Parameters.AddWithValue("@total", scan.Total);
                cmd.Parameters.AddWithValue("@alive", scan.Alive);
                cmd.Parameters.AddWithValue("@risky", scan.Risky);
                cmd.Parameters.AddWithValue("@high", scan.HighRisk);
                scanId = (long)cmd.ExecuteScalar()!;
            }

            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO scan_hosts(scan_id, ip, alive, name, mac, vendor, ports, risk_score, has_prohibited,
                                           os_hint, os_version, model, device_hint, service, switch_port, ipv6, approved, owner)
                    VALUES (@scan, @ip, @alive, @name, @mac, @vendor, @ports, @risk, @proh,
                            @os_hint, @os_version, @model, @device_hint, @service, @switch_port, @ipv6, @approved, @owner);
                    """;
                SqliteParameter pIp = cmd.Parameters.Add("@ip", SqliteType.Text);
                SqliteParameter pAlive = cmd.Parameters.Add("@alive", SqliteType.Integer);
                SqliteParameter pName = cmd.Parameters.Add("@name", SqliteType.Text);
                SqliteParameter pMac = cmd.Parameters.Add("@mac", SqliteType.Text);
                SqliteParameter pVendor = cmd.Parameters.Add("@vendor", SqliteType.Text);
                SqliteParameter pPorts = cmd.Parameters.Add("@ports", SqliteType.Text);
                SqliteParameter pRisk = cmd.Parameters.Add("@risk", SqliteType.Integer);
                SqliteParameter pProh = cmd.Parameters.Add("@proh", SqliteType.Integer);
                SqliteParameter pOsHint = cmd.Parameters.Add("@os_hint", SqliteType.Text);
                SqliteParameter pOsVersion = cmd.Parameters.Add("@os_version", SqliteType.Text);
                SqliteParameter pModel = cmd.Parameters.Add("@model", SqliteType.Text);
                SqliteParameter pDeviceHint = cmd.Parameters.Add("@device_hint", SqliteType.Text);
                SqliteParameter pService = cmd.Parameters.Add("@service", SqliteType.Text);
                SqliteParameter pSwitchPort = cmd.Parameters.Add("@switch_port", SqliteType.Text);
                SqliteParameter pIpv6 = cmd.Parameters.Add("@ipv6", SqliteType.Text);
                SqliteParameter pApproved = cmd.Parameters.Add("@approved", SqliteType.Integer);
                SqliteParameter pOwner = cmd.Parameters.Add("@owner", SqliteType.Text);
                cmd.Parameters.AddWithValue("@scan", scanId);
                foreach (ParsedHost h in scan.Hosts)
                {
                    pIp.Value = h.Ip;
                    pAlive.Value = h.Alive ? 1 : 0;
                    pName.Value = h.Name;
                    pMac.Value = h.Mac;
                    pVendor.Value = h.Vendor;
                    pPorts.Value = h.Ports;
                    pRisk.Value = h.RiskScore;
                    pProh.Value = h.HasProhibited ? 1 : 0;
                    pOsHint.Value = h.OsHint;
                    pOsVersion.Value = h.OsVersion;
                    pModel.Value = h.Model;
                    pDeviceHint.Value = h.DeviceHint;
                    pService.Value = h.Service;
                    pSwitchPort.Value = h.SwitchPort;
                    pIpv6.Value = h.Ipv6;
                    pApproved.Value = h.Approved ? 1 : 0;
                    pOwner.Value = h.Owner;
                    cmd.ExecuteNonQuery();
                }
            }

            tx.Commit();
            return scanId;
        }
    }

    // 사이트별 보관 한도(ScansPerSite)를 적용한다: 오래된 스캔(+호스트 행)과 그 업로드 행, 종류별(html/pdf/json)로
    // 한도를 넘는 업로드 행을 지우고, 커밋 뒤 해당 파일도 디스크에서 지운다. 지운 업로드 수를 돌려준다.
    public int PruneSite(string site)
    {
        var removedPaths = new List<string>();
        lock (_writeLock)
        {
            using SqliteConnection c = Open();
            using SqliteTransaction tx = c.BeginTransaction();

            using (SqliteCommand cmd = c.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    DELETE FROM scan_hosts WHERE scan_id IN
                        (SELECT id FROM scans WHERE site = @site ORDER BY id DESC LIMIT -1 OFFSET @keep);
                    DELETE FROM scans WHERE site = @site AND id NOT IN
                        (SELECT id FROM scans WHERE site = @site ORDER BY id DESC LIMIT @keep);
                    """;
                cmd.Parameters.AddWithValue("@site", site);
                cmd.Parameters.AddWithValue("@keep", _scansPerSite);
                cmd.ExecuteNonQuery();
            }

            // 남은 스캔이 참조하지 않으면서 종류별 최신 N개 밖에 있는 업로드가 정리 대상이다.
            var doomed = new List<long>();
            foreach (string kind in UploadKinds)
            {
                using SqliteCommand sel = c.CreateCommand();
                sel.Transaction = tx;
                sel.CommandText = """
                    SELECT id, rel_path FROM uploads
                    WHERE site = @site AND kind = @kind
                      AND id NOT IN (SELECT upload_id FROM scans WHERE site = @site)
                      AND id NOT IN (SELECT id FROM uploads WHERE site = @site AND kind = @kind ORDER BY id DESC LIMIT @keep)
                    """;
                sel.Parameters.AddWithValue("@site", site);
                sel.Parameters.AddWithValue("@kind", kind);
                sel.Parameters.AddWithValue("@keep", _scansPerSite);
                using SqliteDataReader r = sel.ExecuteReader();
                while (r.Read())
                {
                    doomed.Add(r.GetInt64(0));
                    removedPaths.Add(r.GetString(1));
                }
            }

            foreach (long id in doomed)
            {
                using SqliteCommand del = c.CreateCommand();
                del.Transaction = tx;
                del.CommandText = "DELETE FROM uploads WHERE id = @id";
                del.Parameters.AddWithValue("@id", id);
                del.ExecuteNonQuery();
            }

            tx.Commit();
        }

        foreach (string rel in removedPaths)
        {
            try
            {
                string path = Path.Combine(_dataDir, rel.Replace('/', Path.DirectorySeparatorChar));
                if (File.Exists(path)) File.Delete(path);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return removedPaths.Count;
    }

    public IReadOnlyList<SiteSummary> ListSites(IEnumerable<string> configuredSites)
    {
        var names = new SortedSet<string>(configuredSites, StringComparer.OrdinalIgnoreCase);
        var uploads = new Dictionary<string, (string Last, int Count)>(StringComparer.OrdinalIgnoreCase);

        using SqliteConnection c = Open();
        using (SqliteCommand cmd = c.CreateCommand())
        {
            cmd.CommandText = "SELECT site, MAX(received_at), COUNT(*) FROM uploads GROUP BY site";
            using SqliteDataReader r = cmd.ExecuteReader();
            while (r.Read())
            {
                string site = r.GetString(0);
                names.Add(site);
                uploads[site] = (r.GetString(1), r.GetInt32(2));
            }
        }

        var result = new List<SiteSummary>(names.Count);
        foreach (string site in names)
        {
            uploads.TryGetValue(site, out (string Last, int Count) u);
            ScanSummary? last = ListScans(c, site, 1).FirstOrDefault();
            (long Id, string Kind)? report = LatestReport(c, site);
            result.Add(new SiteSummary(site, u.Last, u.Count, last, report?.Id, report?.Kind));
        }
        return result;
    }

    public IReadOnlyList<ScanSummary> ListScans(string site, int limit)
    {
        using SqliteConnection c = Open();
        return ListScans(c, site, limit);
    }

    private static List<ScanSummary> ListScans(SqliteConnection c, string site, int limit)
    {
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT id, upload_id, site, system_name, received_at, total, alive, risky, high_risk
            FROM scans WHERE site = @site ORDER BY id DESC LIMIT @limit
            """;
        cmd.Parameters.AddWithValue("@site", site);
        cmd.Parameters.AddWithValue("@limit", Math.Clamp(limit, 1, 1000));
        using SqliteDataReader r = cmd.ExecuteReader();
        var list = new List<ScanSummary>();
        while (r.Read()) list.Add(ReadScan(r));
        return list;
    }

    public ScanSummary? GetScan(long id)
    {
        using SqliteConnection c = Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT id, upload_id, site, system_name, received_at, total, alive, risky, high_risk
            FROM scans WHERE id = @id
            """;
        cmd.Parameters.AddWithValue("@id", id);
        using SqliteDataReader r = cmd.ExecuteReader();
        return r.Read() ? ReadScan(r) : null;
    }

    private static ScanSummary ReadScan(SqliteDataReader r) => new(
        r.GetInt64(0), r.GetInt64(1), r.GetString(2), r.GetString(3), r.GetString(4),
        r.GetInt32(5), r.GetInt32(6), r.GetInt32(7), r.GetInt32(8));

    public IReadOnlyList<HostRow> ListHosts(long scanId)
    {
        using SqliteConnection c = Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT ip, alive, name, mac, vendor, ports, risk_score, has_prohibited,
                   os_hint, os_version, model, device_hint, service, switch_port, ipv6, approved, owner
            FROM scan_hosts WHERE scan_id = @scan ORDER BY id
            """;
        cmd.Parameters.AddWithValue("@scan", scanId);
        using SqliteDataReader r = cmd.ExecuteReader();
        var list = new List<HostRow>();
        while (r.Read())
        {
            list.Add(new HostRow(r.GetString(0), r.GetInt32(1) != 0, r.GetString(2), r.GetString(3), r.GetString(4),
                r.GetString(5), r.GetInt32(6), r.GetInt32(7) != 0,
                r.GetString(8), r.GetString(9), r.GetString(10), r.GetString(11), r.GetString(12), r.GetString(13), r.GetString(14),
                r.GetInt32(15) != 0, r.GetString(16)));
        }
        return list;
    }

    public UploadRow? GetUpload(long id)
    {
        using SqliteConnection c = Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, site, file_name, rel_path, kind, size, received_at FROM uploads WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        using SqliteDataReader r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new UploadRow(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetInt64(5), r.GetString(6));
    }

    // 사이트의 업로드 수(종류 지정 가능). 보관 한도 검증/테스트용.
    public int CountUploads(string site, string? kind = null)
    {
        using SqliteConnection c = Open();
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = kind == null
            ? "SELECT COUNT(*) FROM uploads WHERE site = @site"
            : "SELECT COUNT(*) FROM uploads WHERE site = @site AND kind = @kind";
        cmd.Parameters.AddWithValue("@site", site);
        if (kind != null) cmd.Parameters.AddWithValue("@kind", kind);
        return Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    // 사이트의 가장 최근 HTML/PDF 리포트.
    private static (long Id, string Kind)? LatestReport(SqliteConnection c, string site)
    {
        using SqliteCommand cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, kind FROM uploads WHERE site = @site AND kind IN ('html', 'pdf') ORDER BY id DESC LIMIT 1";
        cmd.Parameters.AddWithValue("@site", site);
        using SqliteDataReader r = cmd.ExecuteReader();
        return r.Read() ? (r.GetInt64(0), r.GetString(1)) : null;
    }
}
