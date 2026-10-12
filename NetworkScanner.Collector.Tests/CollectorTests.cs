using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

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
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Collector:DataDir", _dataDir);
            b.UseSetting("Collector:MaxUploadMb", "1");
            b.UseSetting("Collector:Tokens:0:Token", SiteToken);
            b.UseSetting("Collector:Tokens:0:Site", "Office-3F");
            b.UseSetting("Collector:AdminToken", AdminToken);
        });
    }

    public void Dispose()
    {
        _factory.Dispose();
        try { Directory.Delete(_dataDir, true); } catch { }
    }

    private HttpClient Client(string? token)
    {
        HttpClient c = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
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
    public async Task Dashboard_RequiresToken_AndShowsSite()
    {
        using HttpClient c = Client(SiteToken);
        await c.PostAsync("/api/scan", Form("Office-3F_20261012_090000.csv", Csv));

        using HttpClient anon = Client(null);
        HttpResponseMessage noAuth = await anon.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, noAuth.StatusCode);
        Assert.Equal("/login", noAuth.Headers.Location?.ToString());

        HttpResponseMessage page = await anon.GetAsync("/?token=" + SiteToken);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        string html = await page.Content.ReadAsStringAsync();
        Assert.Contains("Office-3F", html);
        Assert.Contains("text/html", page.Content.Headers.ContentType?.MediaType);

        HttpResponseMessage site = await anon.GetAsync("/sites/Office-3F?token=" + SiteToken);
        Assert.Equal(HttpStatusCode.OK, site.StatusCode);
        Assert.Contains("10.0.0.7", await site.Content.ReadAsStringAsync());

        Assert.Equal("ok", await anon.GetStringAsync("/healthz"));
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
}
