using System.Globalization;
using Microsoft.Data.Sqlite;

namespace NetworkScanner.Collector;

public sealed record UploadRow(long Id, string Site, string FileName, string RelPath, string Kind, long Size, string ReceivedAt);

public sealed record ScanSummary(long Id, long UploadId, string Site, string SystemName, string ReceivedAt, int Total, int Alive, int Risky, int HighRisk);

public sealed record HostRow(string Ip, bool Alive, string Name, string Mac, string Vendor, string Ports, int RiskScore, bool HasProhibited);

public sealed record SiteSummary(string Site, string? LastUploadAt, int UploadCount, ScanSummary? LastScan, long? LatestReportId, string? LatestReportKind);

// <DataDir>/collector.db 색인. 쓰기는 한 번에 하나만(SQLite 단일 작성자), 읽기는 WAL 덕분에 동시에 가능하다.
public sealed class CollectorStore
{
    private readonly string _connectionString;
    private readonly object _writeLock = new();
    private readonly int _scansPerSite;

    public CollectorStore(CollectorOptions options)
    {
        Directory.CreateDirectory(options.DataDir);
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
        using SqliteCommand cmd = c.CreateCommand();
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
                has_prohibited INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_scan_hosts_scan ON scan_hosts(scan_id);
            """;
        cmd.ExecuteNonQuery();
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

    // 스캔 요약 + 호스트 행을 한 트랜잭션으로 넣고, 사이트별 보관 한도를 넘는 오래된 스캔을 정리한다.
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
                    INSERT INTO scan_hosts(scan_id, ip, alive, name, mac, vendor, ports, risk_score, has_prohibited)
                    VALUES (@scan, @ip, @alive, @name, @mac, @vendor, @ports, @risk, @proh);
                    """;
                SqliteParameter pIp = cmd.Parameters.Add("@ip", SqliteType.Text);
                SqliteParameter pAlive = cmd.Parameters.Add("@alive", SqliteType.Integer);
                SqliteParameter pName = cmd.Parameters.Add("@name", SqliteType.Text);
                SqliteParameter pMac = cmd.Parameters.Add("@mac", SqliteType.Text);
                SqliteParameter pVendor = cmd.Parameters.Add("@vendor", SqliteType.Text);
                SqliteParameter pPorts = cmd.Parameters.Add("@ports", SqliteType.Text);
                SqliteParameter pRisk = cmd.Parameters.Add("@risk", SqliteType.Integer);
                SqliteParameter pProh = cmd.Parameters.Add("@proh", SqliteType.Integer);
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
                    cmd.ExecuteNonQuery();
                }
            }

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

            tx.Commit();
            return scanId;
        }
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
            SELECT ip, alive, name, mac, vendor, ports, risk_score, has_prohibited
            FROM scan_hosts WHERE scan_id = @scan ORDER BY id
            """;
        cmd.Parameters.AddWithValue("@scan", scanId);
        using SqliteDataReader r = cmd.ExecuteReader();
        var list = new List<HostRow>();
        while (r.Read())
        {
            list.Add(new HostRow(r.GetString(0), r.GetInt32(1) != 0, r.GetString(2), r.GetString(3), r.GetString(4),
                r.GetString(5), r.GetInt32(6), r.GetInt32(7) != 0));
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
