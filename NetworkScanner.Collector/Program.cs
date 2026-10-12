using System.Globalization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.StaticFiles;
using NetworkScanner.Collector;

// 중앙 수집 서버: 여러 사이트의 스캐너(GUI/CLI/서비스)가 HTTPS 업로드로 보낸 리포트를 받아 보관하고,
// CSV는 파싱해 요약을 색인하며, 간단한 대시보드로 보여준다. TLS 종료는 앞단 리버스 프록시에 맡기는 구성을 전제로 한다.
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

CollectorOptions options = CollectorOptions.Load(builder.Configuration, builder.Environment.ContentRootPath);
string? problem = options.Validate();
if (problem != null)
{
    Console.Error.WriteLine("netscan-collector: " + problem);
    return 2;
}

builder.Services.AddSingleton(options);
builder.Services.AddSingleton<TokenRegistry>();
builder.Services.AddSingleton<CollectorStore>();
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxRequestBodySize = options.MaxUploadBytes + 64 * 1024;
    k.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
    k.AddServerHeader = false;
});
builder.Services.Configure<FormOptions>(f =>
{
    f.MultipartBodyLengthLimit = options.MaxUploadBytes;
    f.ValueLengthLimit = 4096;
});

WebApplication app = builder.Build();
var store = app.Services.GetRequiredService<CollectorStore>();
var tokens = app.Services.GetRequiredService<TokenRegistry>();
var contentTypes = new FileExtensionContentTypeProvider();
string[] allowedExt = { ".csv", ".html", ".pdf", ".json" };

app.Logger.LogInformation("collector data dir: {Dir}, sites: {Sites}", options.DataDir, string.Join(", ", tokens.Sites));

app.MapGet("/healthz", () => Results.Text("ok"));

// ---- 업로드(스캐너의 HttpsUploader가 보내는 multipart: name, file) ----
async Task<IResult> ReceiveUpload(HttpRequest request)
{
    Principal? who = tokens.Resolve(request, allowCookie: false, allowQuery: false);
    if (who == null || who.IsAdmin) return Results.Unauthorized();

    if (!request.HasFormContentType) return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    if (request.ContentLength > options.MaxUploadBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

    IFormCollection form;
    try { form = await request.ReadFormAsync(); }
    catch (Exception ex) when (ex is InvalidDataException || ex is BadHttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    IFormFile? file = form.Files.GetFile("file") ?? form.Files.FirstOrDefault();
    if (file == null || file.Length == 0) return Results.BadRequest(new { error = "file is required" });
    if (file.Length > options.MaxUploadBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

    string name = FileNames.Sanitize(form["name"].FirstOrDefault() ?? file.FileName, "upload");
    string ext = Path.GetExtension(name).ToLowerInvariant();
    if (!allowedExt.Contains(ext)) return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    string kind = ext.TrimStart('.');

    DateTime now = DateTime.UtcNow;
    string site = FileNames.Sanitize(who.Site, "site");
    string relDir = Path.Combine("sites", site, now.ToString("yyyy", CultureInfo.InvariantCulture), now.ToString("MM", CultureInfo.InvariantCulture));
    string dir = Path.Combine(options.DataDir, relDir);
    Directory.CreateDirectory(dir);

    // 같은 이름이 있으면 -2, -3… 을 붙인다.
    string stem = Path.GetFileNameWithoutExtension(name);
    string final = name;
    for (int i = 2; File.Exists(Path.Combine(dir, final)); i++) final = $"{stem}-{i}{ext}";
    string fullPath = Path.Combine(dir, final);
    await using (FileStream fs = File.Create(fullPath))
    {
        await file.CopyToAsync(fs);
    }

    long uploadId = store.AddUpload(who.Site, final, Path.Combine(relDir, final).Replace('\\', '/'), kind, file.Length, now);
    if (kind == "csv")
    {
        try
        {
            ParsedScan? parsed = ScanCsvParser.Parse(await File.ReadAllTextAsync(fullPath));
            if (parsed != null) store.AddScan(uploadId, who.Site, ScanCsvParser.SystemNameFromFileName(final), now, parsed);
        }
        catch (Exception ex)
        {
            app.Logger.LogWarning("csv parse failed for {File}: {Message}", final, ex.Message);
        }
    }
    app.Logger.LogInformation("upload {Id} from {Site}: {File} ({Bytes} bytes, {Kind})", uploadId, who.Site, final, file.Length, kind);
    return Results.Created($"/api/uploads/{uploadId}", new { id = uploadId, site = who.Site, kind, bytes = file.Length });
}
app.MapPost("/api/scan", ReceiveUpload).DisableAntiforgery();
app.MapPost("/api/upload", ReceiveUpload).DisableAntiforgery();
app.MapPost("/", ReceiveUpload).DisableAntiforgery();

// ---- 조회 API ----
app.MapGet("/api/sites", (HttpRequest req) =>
{
    Principal? who = tokens.Resolve(req, allowCookie: false, allowQuery: false);
    if (who == null) return Results.Unauthorized();
    var sites = store.ListSites(tokens.Sites).Where(s => who.CanView(s.Site)).ToList();
    return Results.Json(sites);
});

app.MapGet("/api/sites/{site}/scans", (HttpRequest req, string site, int? limit) =>
{
    Principal? who = tokens.Resolve(req, allowCookie: false, allowQuery: false);
    if (who == null) return Results.Unauthorized();
    if (!who.CanView(site)) return Results.Forbid();
    return Results.Json(store.ListScans(site, Math.Clamp(limit ?? 50, 1, 500)));
});

app.MapGet("/api/sites/{site}/scans/{id:long}/hosts", (HttpRequest req, string site, long id) =>
{
    Principal? who = tokens.Resolve(req, allowCookie: false, allowQuery: false);
    if (who == null) return Results.Unauthorized();
    ScanSummary? scan = store.GetScan(id);
    if (scan == null || !string.Equals(scan.Site, site, StringComparison.OrdinalIgnoreCase)) return Results.NotFound();
    if (!who.CanView(site)) return Results.Forbid();
    return Results.Json(store.ListHosts(id));
});

IResult Download(HttpRequest req, long id, bool allowCookie)
{
    Principal? who = tokens.Resolve(req, allowCookie, allowQuery: allowCookie);
    if (who == null) return Results.Unauthorized();
    UploadRow? row = store.GetUpload(id);
    if (row == null) return Results.NotFound();
    if (!who.CanView(row.Site)) return Results.Forbid();
    string path = Path.Combine(options.DataDir, row.RelPath.Replace('/', Path.DirectorySeparatorChar));
    if (!File.Exists(path)) return Results.NotFound();
    if (!contentTypes.TryGetContentType(row.FileName, out string? ct)) ct = "application/octet-stream";
    bool inline = row.Kind is "html" or "pdf";
    return inline ? Results.File(path, ct) : Results.File(path, ct, row.FileName);
}
app.MapGet("/api/uploads/{id:long}", (HttpRequest req, long id) => Download(req, id, allowCookie: false));
app.MapGet("/reports/{id:long}", (HttpRequest req, long id) => Download(req, id, allowCookie: true));

// ---- 대시보드(쿠키 또는 ?token= 으로 로그인) ----
app.MapGet("/login", () => Results.Content(Dashboard.Login(null), "text/html; charset=utf-8"));
app.MapPost("/login", async (HttpRequest req, HttpResponse res) =>
{
    IFormCollection form = await req.ReadFormAsync();
    string? token = form["token"].FirstOrDefault();
    if (tokens.Match(token) == null) return Results.Content(Dashboard.Login("Invalid token."), "text/html; charset=utf-8", null, StatusCodes.Status401Unauthorized);
    res.Cookies.Append(TokenRegistry.CookieName, token!, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = req.IsHttps, MaxAge = TimeSpan.FromDays(30) });
    return Results.Redirect("/");
}).DisableAntiforgery();
app.MapPost("/logout", (HttpResponse res) =>
{
    res.Cookies.Delete(TokenRegistry.CookieName);
    return Results.Redirect("/login");
}).DisableAntiforgery();

app.MapGet("/", (HttpRequest req, HttpResponse res) =>
{
    Principal? who = tokens.Resolve(req, allowCookie: true, allowQuery: true);
    if (who == null) return Results.Redirect("/login");
    if (req.Query.ContainsKey("token"))
        res.Cookies.Append(TokenRegistry.CookieName, req.Query["token"]!, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = req.IsHttps, MaxAge = TimeSpan.FromDays(30) });
    var sites = store.ListSites(tokens.Sites).Where(s => who.CanView(s.Site)).ToList();
    return Results.Content(Dashboard.Index(sites, who), "text/html; charset=utf-8");
});

app.MapGet("/sites/{site}", (HttpRequest req, string site) =>
{
    Principal? who = tokens.Resolve(req, allowCookie: true, allowQuery: true);
    if (who == null) return Results.Redirect("/login");
    if (!who.CanView(site)) return Results.Content(Dashboard.Forbidden(site, who), "text/html; charset=utf-8", null, StatusCodes.Status403Forbidden);
    var scans = store.ListScans(site, 50);
    var hosts = scans.Count > 0 ? store.ListHosts(scans[0].Id) : Array.Empty<HostRow>();
    SiteSummary? summary = store.ListSites(tokens.Sites).FirstOrDefault(s => string.Equals(s.Site, site, StringComparison.OrdinalIgnoreCase));
    (long, string)? report = summary?.LatestReportId is long rid && summary.LatestReportKind != null ? (rid, summary.LatestReportKind) : null;
    return Results.Content(Dashboard.Site(site, scans, hosts, report, who), "text/html; charset=utf-8");
});

app.Run();
return 0;

// 통합 테스트(WebApplicationFactory)가 진입점을 찾을 수 있도록 공개 partial 클래스를 둔다.
public partial class Program { }
