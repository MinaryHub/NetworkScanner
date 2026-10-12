using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using NetworkScanner;

namespace NetworkScanner.Collector.Tests;

// 임시 DataDir에 떠 있는 수집 서버에 스캐너 형식 CSV를 올리고 API/대시보드를 확인한다.
public sealed class CollectorTests : IDisposable
{
    private const string SiteToken = "site-token-0123456789abcdef";
    private const string AdminToken = "admin-token-0123456789abcdef";
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "nstest-collector-" + Guid.NewGuid().ToString("N"));
    private readonly WebApplicationFactory<Program> _factory;

    public CollectorTests()
    {
        Directory.CreateDirectory(_dataDir);
        _factory = NewFactory(_dataDir);
    }

    private static WebApplicationFactory<Program> NewFactory(string dataDir, Action<IWebHostBuilder>? extra = null)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Collector:DataDir", dataDir);
            b.UseSetting("Collector:MaxUploadMb", "1");
            b.UseSetting("Collector:Tokens:0:Token", SiteToken);
            b.UseSetting("Collector:Tokens:0:Site", "Office-3F");
            b.UseSetting("Collector:AdminToken", AdminToken);
            extra?.Invoke(b);
        });
    }

    public void Dispose()
    {
        _factory.Dispose();
        try { Directory.Delete(_dataDir, true); } catch { }
    }

    private HttpClient Client(string? token) => Client(_factory, token);

    private static HttpClient Client(WebApplicationFactory<Program> factory, string? token)
    {
        HttpClient c = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (token != null) c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    private const string Csv =
        "IPAddress,Port,SystemName,Description,Commitdate,Alive,MacAddress,Vendor,RoundTime,Service,Ttl,HasProhibitedPort,OsHint,DeviceHint,SysDescr,IdentitySource,RiskScore,Findings,Approved,Owner\r\n" +
        "10.0.0.1,22/80/,gw,\"note, with comma\",2026/10/12 09:00:00,True,00-11-22-33-44-55,Cisco,1,SSH-2.0-OpenSSH_9.9,255,False,,,,,0,,True,ops\r\n" +
        "10.0.0.7,445/31337/,pc7,,2026/10/12 09:00:00,True,AA-BB-CC-DD-EE-FF,Dell,3,,128,True,,,,,65,,False,\r\n" +
        "10.0.0.9,,nas,,2026/10/12 09:00:00,False,,,Timeout,,0,False,,,,,0,,False,\r\n";

    private static MultipartFormDataContent Form(string name, string content)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(name), "name");
        var file = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
        file.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        form.Add(file, "file", name);
        return form;
    }

    // 로그인 폼으로 쿠키 세션을 만든다(HttpClient가 Set-Cookie를 보관한다).
    private static async Task SignInAsync(HttpClient c, string token)
    {
        HttpResponseMessage login = await c.PostAsync("/login", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", token) }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/", login.Headers.Location?.ToString());
    }

    [Fact]
    public async Task Upload_WithValidToken_IsIndexedAndVisible()
    {
        using HttpClient c = Client(SiteToken);
        HttpResponseMessage resp = await c.PostAsync("/api/scan", Form("Office-3F_20261012_090000.csv", Csv));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        using JsonDocument created = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("Office-3F", created.RootElement.GetProperty("site").GetString());
        Assert.Equal("csv", created.RootElement.GetProperty("kind").GetString());

        using JsonDocument sites = JsonDocument.Parse(await c.GetStringAsync("/api/sites"));
        JsonElement site = sites.RootElement.EnumerateArray().Single();
        Assert.Equal("Office-3F", site.GetProperty("site").GetString());
        JsonElement last = site.GetProperty("lastScan");
        Assert.Equal(3, last.GetProperty("total").GetInt32());
        Assert.Equal(2, last.GetProperty("alive").GetInt32());
        Assert.Equal(1, last.GetProperty("risky").GetInt32());
        Assert.Equal(1, last.GetProperty("highRisk").GetInt32());

        long scanId = last.GetProperty("id").GetInt64();
        using JsonDocument hosts = JsonDocument.Parse(await c.GetStringAsync($"/api/sites/Office-3F/scans/{scanId}/hosts"));
        Assert.Equal(3, hosts.RootElement.GetArrayLength());

        // 저장 위치: sites/<site>/<yyyy>/<MM>/
        string[] stored = Directory.GetFiles(Path.Combine(_dataDir, "sites", "Office-3F"), "*.csv", SearchOption.AllDirectories);
        Assert.Single(stored);
    }

    [Fact]
    public async Task Upload_RejectsBadTokenExtensionAndOversize()
    {
        using HttpClient bad = Client("wrong-token-0123456789abcdef");
        Assert.Equal(HttpStatusCode.Unauthorized, (await bad.PostAsync("/api/scan", Form("a.csv", Csv))).StatusCode);

        using HttpClient c = Client(SiteToken);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await c.PostAsync("/api/scan", Form("evil.exe", "x"))).StatusCode);

        string big = new string('a', 2 * 1024 * 1024);
        HttpResponseMessage oversize = await c.PostAsync("/api/scan", Form("big.csv", big));
        Assert.True(oversize.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.BadRequest, oversize.StatusCode.ToString());

        // 관리 토큰은 조회 전용: 업로드에는 쓸 수 없다
        using HttpClient admin = Client(AdminToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await admin.PostAsync("/api/scan", Form("a.csv", Csv))).StatusCode);
    }

    [Fact]
    public async Task Upload_SanitizesFileNames()
    {
        using HttpClient c = Client(SiteToken);
        HttpResponseMessage resp = await c.PostAsync("/api/scan", Form("../../etc/passwd.csv", Csv));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.False(File.Exists(Path.Combine(_dataDir, "etc", "passwd.csv")));
        Assert.Single(Directory.GetFiles(Path.Combine(_dataDir, "sites", "Office-3F"), "*.csv", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Dashboard_RequiresCookieLogin_AndIgnoresQueryToken()
    {
        using HttpClient c = Client(SiteToken);
        await c.PostAsync("/api/scan", Form("Office-3F_20261012_090000.csv", Csv));

        using HttpClient anon = Client(null);
        HttpResponseMessage noAuth = await anon.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, noAuth.StatusCode);
        Assert.Equal("/login", noAuth.Headers.Location?.ToString());

        // URL 토큰은 더 이상 로그인 수단이 아니다
        HttpResponseMessage viaQuery = await anon.GetAsync("/?token=" + SiteToken);
        Assert.Equal(HttpStatusCode.Redirect, viaQuery.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await anon.GetAsync("/sites/Office-3F?token=" + SiteToken)).StatusCode);

        await SignInAsync(anon, SiteToken);
        HttpResponseMessage page = await anon.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        string html = await page.Content.ReadAsStringAsync();
        Assert.Contains("Office-3F", html);
        Assert.Contains("text/html", page.Content.Headers.ContentType?.MediaType);

        HttpResponseMessage site = await anon.GetAsync("/sites/Office-3F");
        Assert.Equal(HttpStatusCode.OK, site.StatusCode);
        string siteHtml = await site.Content.ReadAsStringAsync();
        Assert.Contains("10.0.0.7", siteHtml);
        Assert.Contains("<th>Model</th><th>OS</th>", siteHtml);
        Assert.Contains("<th>Service</th>", siteHtml);
        Assert.Contains("SSH-2.0-OpenSSH_9.9", siteHtml);

        Assert.Equal("ok", await anon.GetStringAsync("/healthz"));

        // 로그아웃하면 다시 로그인 페이지로
        Assert.Equal(HttpStatusCode.Redirect, (await anon.PostAsync("/logout", new StringContent(""))).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await anon.GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task Dashboard_ReportLinks_WorkWithCookieSession()
    {
        using HttpClient c = Client(SiteToken);
        await c.PostAsync("/api/scan", Form("Office-3F_20261012_090000.csv", Csv));
        HttpResponseMessage up = await c.PostAsync("/api/scan", Form("Office-3F_20261012_090000_report.html", "<html><body>report-body</body></html>"));
        using JsonDocument created = JsonDocument.Parse(await up.Content.ReadAsStringAsync());
        long reportId = created.RootElement.GetProperty("id").GetInt64();

        using HttpClient browser = Client(null);
        await SignInAsync(browser, SiteToken);

        string index = await browser.GetStringAsync("/");
        Assert.Contains($"href=\"/reports/{reportId}\"", index);
        Assert.DoesNotContain("/api/uploads/", index);
        string site = await browser.GetStringAsync("/sites/Office-3F");
        Assert.Contains($"href=\"/reports/{reportId}\"", site);
        Assert.DoesNotContain("/api/uploads/", site);

        // 대시보드가 가리키는 링크를 쿠키 세션으로 그대로 열 수 있어야 한다
        HttpResponseMessage report = await browser.GetAsync($"/reports/{reportId}");
        Assert.Equal(HttpStatusCode.OK, report.StatusCode);
        Assert.Contains("report-body", await report.Content.ReadAsStringAsync());

        // Bearer 전용 API 경로는 쿠키로는 열리지 않는다(기존 동작 유지)
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync($"/api/uploads/{reportId}")).StatusCode);
        // 쿠키 없이 /reports 는 401
        using HttpClient anon = Client(null);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/reports/{reportId}")).StatusCode);
    }

    [Fact]
    public async Task Download_ReturnsStoredFile_OnlyToItsSiteOrAdmin()
    {
        using HttpClient c = Client(SiteToken);
        HttpResponseMessage resp = await c.PostAsync("/api/scan", Form("report.html", "<html><body>hi</body></html>"));
        using JsonDocument created = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        long id = created.RootElement.GetProperty("id").GetInt64();

        Assert.Contains("hi", await c.GetStringAsync($"/api/uploads/{id}"));
        using HttpClient admin = Client(AdminToken);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync($"/api/uploads/{id}")).StatusCode);
        using HttpClient anon = Client(null);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/api/uploads/{id}")).StatusCode);
    }

    [Fact]
    public async Task Login_IsRateLimited_AfterTenFailures()
    {
        using HttpClient anon = Client(null);
        for (int i = 0; i < 10; i++)
        {
            HttpResponseMessage r = await anon.PostAsync("/login", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", "wrong-" + i) }));
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }
        // 11번째부터는 올바른 토큰이라도 429
        HttpResponseMessage blocked = await anon.PostAsync("/login", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", SiteToken) }));
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Contains("Too many", await blocked.Content.ReadAsStringAsync());
        // Bearer API는 영향을 받지 않는다
        using HttpClient c = Client(SiteToken);
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/api/sites")).StatusCode);
    }

    [Fact]
    public void LoginRateLimiter_WindowExpires_AndSuccessResets()
    {
        var limiter = new LoginRateLimiter(maxFailures: 3, window: TimeSpan.FromMinutes(15));
        DateTime t0 = new(2026, 10, 12, 9, 0, 0, DateTimeKind.Utc);
        Assert.False(limiter.IsBlocked("1.2.3.4", t0));
        Assert.Equal(2, limiter.RecordFailure("1.2.3.4", t0));
        Assert.Equal(1, limiter.RecordFailure("1.2.3.4", t0.AddMinutes(1)));
        Assert.Equal(0, limiter.RecordFailure("1.2.3.4", t0.AddMinutes(2)));
        Assert.True(limiter.IsBlocked("1.2.3.4", t0.AddMinutes(3)));
        Assert.False(limiter.IsBlocked("5.6.7.8", t0.AddMinutes(3)));   // 다른 클라이언트는 무관
        Assert.False(limiter.IsBlocked("1.2.3.4", t0.AddMinutes(15)));  // 창이 지나면 해제
        limiter.RecordFailure("1.2.3.4", t0.AddMinutes(20));
        limiter.Reset("1.2.3.4");
        Assert.Equal(2, limiter.RecordFailure("1.2.3.4", t0.AddMinutes(21)));
    }

    [Fact]
    public async Task Retention_DeletesOldScans_UploadRows_AndFiles()
    {
        string dir = Path.Combine(Path.GetTempPath(), "nstest-collector-ret-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            using WebApplicationFactory<Program> factory = NewFactory(dir, b => b.UseSetting("Collector:ScansPerSite", "2"));
            using HttpClient c = Client(factory, SiteToken);
            for (int i = 1; i <= 4; i++)
            {
                HttpResponseMessage r = await c.PostAsync("/api/scan", Form($"Office-3F_2026101{i}_090000.csv", Csv));
                Assert.Equal(HttpStatusCode.Created, r.StatusCode);
                HttpResponseMessage h = await c.PostAsync("/api/scan", Form($"Office-3F_2026101{i}_090000_report.html", $"<html>{i}</html>"));
                Assert.Equal(HttpStatusCode.Created, h.StatusCode);
            }

            using JsonDocument scans = JsonDocument.Parse(await c.GetStringAsync("/api/sites/Office-3F/scans"));
            Assert.Equal(2, scans.RootElement.GetArrayLength());

            // 남은 스캔의 CSV는 내려받을 수 있고, 밀려난 업로드는 404
            long keptUpload = scans.RootElement[0].GetProperty("uploadId").GetInt64();
            Assert.Equal(HttpStatusCode.OK, (await c.GetAsync($"/api/uploads/{keptUpload}")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/uploads/1")).StatusCode);

            string siteDir = Path.Combine(dir, "sites", "Office-3F");
            Assert.Equal(2, Directory.GetFiles(siteDir, "*.csv", SearchOption.AllDirectories).Length);
            Assert.Equal(2, Directory.GetFiles(siteDir, "*.html", SearchOption.AllDirectories).Length);

            var store = factory.Services.GetRequiredService<CollectorStore>();
            Assert.Equal(2, store.CountUploads("Office-3F", "csv"));
            Assert.Equal(2, store.CountUploads("Office-3F", "html"));
            Assert.Equal(4, store.CountUploads("Office-3F"));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Theory]
    [InlineData("Office-PC_20261011_120000.csv", "Office-PC")]
    [InlineData("Office_PC_20261011_120000.csv", "Office_PC")]
    [InlineData("Office_PC_20261011_120000_(SCHEDULING).csv", "Office_PC")]
    [InlineData("Office_PC_20261011_120000_(SCHEDULING)-2.csv", "Office_PC")]
    [InlineData("Office_PC_20261011_120000_report.html", "Office_PC")]
    [InlineData("Office_PC_20261011_120000_report.pdf", "Office_PC")]
    [InlineData("plain.csv", "plain")]
    [InlineData("a_b_c.csv", "a_b_c")]
    public void SystemNameFromFileName_ParsesFromTheRight(string fileName, string expected)
    {
        Assert.Equal(expected, ScanCsvParser.SystemNameFromFileName(fileName));
    }

    [Fact]
    public void Parse_ReadsEveryColumn_FromScanEngineCsv()
    {
        var hosts = new List<IPInfo>
        {
            new()
            {
                Ip = "10.0.0.7", Alive = true, SystemName = "pc7", Macaddr = "AA-BB-CC-DD-EE-FF", Vendor = "Dell", Ports = "445/3389/",
                RiskScore = 65, HasProhibitedPort = true, OsHint = "Windows", OsVersion = "Windows 11 22631", Model = "OptiPlex 7010",
                DeviceHint = "workstation", Service = "smb, \"rdp\"", SwitchPort = "sw1:Gi1/0/7", Ipv6 = "fe80::1", Approved = true, Owner = "Kim",
                Description = "desk, 3F", RountTime = "3",
            },
            new() { Ip = "10.0.0.9", Alive = false, SystemName = "nas" },
        };
        string csv = ScanEngine.BuildCsv(hosts);
        Assert.StartsWith("IPAddress,", csv);

        ParsedScan? parsed = ScanCsvParser.Parse(csv);
        Assert.NotNull(parsed);
        Assert.Equal(2, parsed!.Total);
        Assert.Equal(1, parsed.Alive);
        Assert.Equal(1, parsed.Risky);
        Assert.Equal(1, parsed.HighRisk);

        ParsedHost h = parsed.Hosts[0];
        Assert.Equal("10.0.0.7", h.Ip);
        Assert.True(h.Alive);
        Assert.Equal("pc7", h.Name);
        Assert.Equal("AA-BB-CC-DD-EE-FF", h.Mac);
        Assert.Equal("Dell", h.Vendor);
        Assert.Equal("445/3389/", h.Ports);
        Assert.Equal(65, h.RiskScore);
        Assert.True(h.HasProhibited);
        Assert.Equal("Windows", h.OsHint);
        Assert.Equal("Windows 11 22631", h.OsVersion);
        Assert.Equal("OptiPlex 7010", h.Model);
        Assert.Equal("workstation", h.DeviceHint);
        Assert.Equal("smb, \"rdp\"", h.Service);
        Assert.Equal("sw1:Gi1/0/7", h.SwitchPort);
        Assert.Equal("fe80::1", h.Ipv6);
        Assert.True(h.Approved);
        Assert.Equal("Kim", h.Owner);

        Assert.False(parsed.Hosts[1].Alive);
        Assert.Equal("", parsed.Hosts[1].Model);
    }

    [Fact]
    public async Task Hosts_Api_ReturnsExtendedColumns_AfterUpload()
    {
        var hosts = new List<IPInfo>
        {
            new() { Ip = "10.0.0.7", Alive = true, SystemName = "pc7", Model = "OptiPlex", OsVersion = "Windows 11", Service = "smb", Owner = "Kim", Approved = true, SwitchPort = "Gi1/0/7" },
        };
        using HttpClient c = Client(SiteToken);
        HttpResponseMessage r = await c.PostAsync("/api/scan", Form("Office_PC_20261012_090000.csv", ScanEngine.BuildCsv(hosts)));
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);

        using JsonDocument scans = JsonDocument.Parse(await c.GetStringAsync("/api/sites/Office-3F/scans"));
        JsonElement scan = scans.RootElement[0];
        Assert.Equal("Office_PC", scan.GetProperty("systemName").GetString());
        long id = scan.GetProperty("id").GetInt64();

        using JsonDocument rows = JsonDocument.Parse(await c.GetStringAsync($"/api/sites/Office-3F/scans/{id}/hosts"));
        JsonElement row = rows.RootElement[0];
        Assert.Equal("OptiPlex", row.GetProperty("model").GetString());
        Assert.Equal("Windows 11", row.GetProperty("osVersion").GetString());
        Assert.Equal("Windows 11", row.GetProperty("os").GetString());
        Assert.Equal("smb", row.GetProperty("service").GetString());
        Assert.Equal("Kim", row.GetProperty("owner").GetString());
        Assert.Equal("Gi1/0/7", row.GetProperty("switchPort").GetString());
        Assert.True(row.GetProperty("approved").GetBoolean());
    }

    [Fact]
    public void Schema_MigratesV1Database_ByAddingColumns()
    {
        string dir = Path.Combine(Path.GetTempPath(), "nstest-collector-mig-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // v1 스키마(열 9개)로 만든 DB에 행을 하나 넣어 둔다
            string db = Path.Combine(dir, "collector.db");
            using (var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = db, Mode = SqliteOpenMode.ReadWriteCreate }.ToString()))
            {
                c.Open();
                using SqliteCommand cmd = c.CreateCommand();
                cmd.CommandText = """
                    CREATE TABLE uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, file_name TEXT NOT NULL, rel_path TEXT NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL, received_at TEXT NOT NULL);
                    CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id INTEGER NOT NULL, site TEXT NOT NULL, system_name TEXT NOT NULL, received_at TEXT NOT NULL, total INTEGER NOT NULL, alive INTEGER NOT NULL, risky INTEGER NOT NULL, high_risk INTEGER NOT NULL);
                    CREATE TABLE scan_hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ip TEXT NOT NULL, alive INTEGER NOT NULL, name TEXT NOT NULL, mac TEXT NOT NULL, vendor TEXT NOT NULL, ports TEXT NOT NULL, risk_score INTEGER NOT NULL, has_prohibited INTEGER NOT NULL);
                    INSERT INTO uploads(site, file_name, rel_path, kind, size, received_at) VALUES ('S', 'a.csv', 'sites/S/a.csv', 'csv', 1, '2026-10-12T09:00:00Z');
                    INSERT INTO scans(upload_id, site, system_name, received_at, total, alive, risky, high_risk) VALUES (1, 'S', 'old', '2026-10-12T09:00:00Z', 1, 1, 0, 0);
                    INSERT INTO scan_hosts(scan_id, ip, alive, name, mac, vendor, ports, risk_score, has_prohibited) VALUES (1, '10.0.0.1', 1, 'gw', '', 'Cisco', '22/', 0, 0);
                    """;
                cmd.ExecuteNonQuery();
            }
            SqliteConnection.ClearAllPools();

            var store = new CollectorStore(new CollectorOptions { DataDir = dir });
            Assert.Equal(2, store.UserVersion);
            HostRow row = Assert.Single(store.ListHosts(1));
            Assert.Equal("10.0.0.1", row.Ip);
            Assert.Equal("", row.Model);
            Assert.Equal("", row.Os);
            Assert.False(row.Approved);

            // 새 열에 값을 넣을 수 있다
            long scanId = store.AddScan(1, "S", "new", DateTime.UtcNow, new ParsedScan(1, 1, 0, 0, new[]
            {
                new ParsedHost("10.0.0.2", true, "pc", "", "Dell", "445/", 0, false, Model: "OptiPlex", OsVersion: "Windows 11", Service: "smb"),
            }));
            HostRow added = Assert.Single(store.ListHosts(scanId));
            Assert.Equal("OptiPlex", added.Model);
            Assert.Equal("Windows 11", added.Os);
            SqliteConnection.ClearAllPools();
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}
