using System.Globalization;
using System.Net;
using System.Text;
using KetworkScanner;
using KetworkScanner.Cli;
using KetworkScanner.History;
using KetworkScanner.Notifications;

// 헤드리스/서버 환경에서 GUI 없이 대역을 스캔하는 CLI. KetworkScanner.Core의 ScanEngine을 그대로 구동한다.
// 진행 상황은 stderr로, 최종 결과는 stdout으로 내보내 파이프 연동(특히 JSON)이 깨지지 않게 한다.

Console.OutputEncoding = Encoding.UTF8;

// Windows 업데이트 도우미 모드(부모 종료 후 파일 교체).
if (args.Length > 0 && args[0] == "--apply-update")
{
    return KetworkScanner.Updates.HeadlessUpdater.RunApplyHelper(args[1..]);
}

var options = CliOptions.Parse(args);
if (options.ShowHelp)
{
    CliOptions.PrintHelp();
    return 0;
}
if (options.Error != null)
{
    Console.Error.WriteLine("error: " + options.Error);
    Console.Error.WriteLine("Run 'netscan --help' for usage.");
    return 2;
}

// 오류는 로그 파일 외에 stderr로도 흘려보낸다.
OUIInfo.OnError = m => Console.Error.WriteLine("warn: " + m);
KetworkScanner.Network.IcmpPinger.OnError = m => Console.Error.WriteLine("warn: " + m);
PortReferenceLoader.OnError = m => Console.Error.WriteLine("warn: " + m);
AppSettingsStore.OnError = m => Console.Error.WriteLine("warn: " + m);
AppLogger.Sink += (level, _, m) => { if (level >= KetworkScanner.LogLevel.Error) Console.Error.WriteLine("error: " + m); };

// --use-settings: GUI와 같은 settings.json(대역/포트/업로드/알림)을 그대로 사용한다. 명령행 옵션이 있으면 그것이 우선한다.
AppSettingsData? saved = options.UseSettings ? AppSettingsStore.LoadSettings() : null;
Localization.Current = options.LanguageSet ? options.Language : (saved?.Language ?? options.Language);
if (saved != null)
{
    // GUI의 설정 화면과 같은 검사를 거쳐 잘못된 값을 경고로 알린다(스캔은 계속한다).
    foreach (string problem in saved.Validate())
        Console.Error.WriteLine("warn: settings.json: " + problem);
}

switch (options.Command)
{
    case CliCommand.History: return RunHistory(options);
    case CliCommand.Assets: return RunAssets(options);
    case CliCommand.Alerts: return RunAlerts(options);
    case CliCommand.Settings: return RunSettings(options);
    case CliCommand.Diag: return RunDiag(options);
    case CliCommand.Update: return await RunUpdateAsync(options);
    case CliCommand.RefData: return await RunRefDataAsync(options);
}

// 스캔 대역 결정: --range → settings.json → 로컬 서브넷 자동 감지 순.
var ranges = new ScanRangeList();
if (options.Ranges.Count > 0)
{
    foreach (var r in options.Ranges) ranges.AddItem(r);
}
else if (saved != null)
{
    foreach (var r in AppSettingsStore.LoadScanRanges()) ranges.AddItem(r);
}
if (ranges.Count == 0)
{
    ScanRangeInfo? local = LocalNetworkInfo.GetLocalSubnetRange();
    if (local == null)
    {
        Console.Error.WriteLine("error: no --range given and local subnet could not be detected.");
        return 2;
    }
    ranges.AddItem(local);
    Console.Error.WriteLine($"info: no --range given; using detected local subnet {local.StartIP} ~ {local.EndIP}");
}

// 참조 데이터 자동 갱신(설정에 켜져 있고 주기가 지났을 때만). 실패해도 스캔은 번들/기존 데이터로 계속한다.
if (saved != null && saved.ReferenceData.AutoUpdate)
{
    try
    {
        using var refCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var refResult = await CreateRefDataUpdater(saved).CheckAndUpdateAsync(false, TimeSpan.FromHours(Math.Max(1, saved.ReferenceData.CheckIntervalHours)), refCts.Token);
        if (refResult.Changed && !options.Quiet)
            Console.Error.WriteLine("info: reference data updated: " + string.Join(", ", refResult.Updated.Select(f => f.Name + " " + f.Version)));
        else if (refResult.Error != null && !options.Quiet)
            Console.Error.WriteLine("warn: reference data check failed: " + refResult.Error);
    }
    catch (Exception ex) { if (!options.Quiet) Console.Error.WriteLine("warn: reference data check failed: " + ex.Message); }
}

var oui = new OUIInfo();
oui.LoadInfo();
var (reserved, prohibited) = PortReferenceLoader.Load();

string portList = options.PortsSet ? options.Ports : (saved?.UsePortChecking == true ? saved.PortList : "");
var config = new CliConfig
{
    Ranges = ranges,
    PortList = portList,
    UsePorts = portList.Length > 0,
    SystemName = options.SystemName ?? (string.IsNullOrWhiteSpace(saved?.SystemName) ? SafeHostName() : saved!.SystemName),
    Reserved = reserved,
    Prohibited = prohibited,
    Upload = options.Upload && saved != null ? saved.Upload : new KetworkScanner.Upload.UploadSettings(),
};

var items = new IPInfoList();
var services = options.NoDiscovery
    ? ScanServices.CreateDefault(withHistory: !options.NoHistory)
    : ScanServices.CreateDefault(saved ?? new AppSettingsData(), withHistory: !options.NoHistory);
// 설정 → --profile → 명시적 옵션 순으로 적용해 --parallelism 같은 명시값이 프로필을 이긴다.
var engineOptions = CliScanOptions.Build(options, saved);
var engine = new ScanEngine(items, oui, config, services, engineOptions);

bool quiet = options.Quiet || Console.IsErrorRedirected;
engine.Message += m => { if (!quiet) Console.Error.WriteLine(m); };
Notifier? notifier = options.Notify && saved != null ? new Notifier(saved.Notifications) : null;
engine.ScanChangesDetected += changes =>
{
    foreach (var c in changes)
        Console.Error.WriteLine("change: " + ScanDiff.Describe(c));
};
// 알림 운영 규칙(중복/확인/스누즈/점검 시간대)을 거친 것만 외부 채널로 보낸다. 이력 DB가 없으면(--no-history) 전부 보낸다.
engine.AlertsProcessed += outcome =>
{
    if (outcome.Resolved > 0) Console.Error.WriteLine($"alerts: {outcome.Resolved} resolved, {outcome.Suppressed.Count} suppressed{(outcome.InMaintenance ? " (maintenance window)" : "")}");
    if (notifier != null && outcome.ChangesToNotify.Count > 0)
    {
        try { notifier.NotifyChangesAsync(config.GetSystemName(), outcome.ChangesToNotify, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (Exception ex) { Console.Error.WriteLine("warn: notify failed: " + ex.Message); }
    }
};
if (options.NoHistory && notifier != null)
{
    engine.ScanChangesDetected += changes =>
    {
        try { notifier.NotifyChangesAsync(config.GetSystemName(), changes, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (Exception ex) { Console.Error.WriteLine("warn: notify failed: " + ex.Message); }
    };
}

Console.CancelKeyPress += (_, e) => { e.Cancel = true; engine.ScanningStop(); };

engine.InitFromConfig();
// --scheduled: GUI의 예약 스캔과 동일하게 CSV/HTML/PDF 리포트를 env/에 남기고 업로드 설정이면 업로드한다(cron/서비스용).
bool started = options.Scheduled
    ? engine.StartSchedulingScan(config.GetSystemName())
    : engine.StartRefreshAllRange(config.GetSystemName());
if (!started)
{
    Console.Error.WriteLine("error: scan could not be started.");
    return 1;
}
if (engine.Scanning != null) await engine.Scanning;

// 결과 스냅샷을 원하는 형식으로 출력한다.
string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
List<IPInfo> results;
lock (engine.ItemsSyncRoot) results = new(items);

// --upload 없이 --scheduled 만 주면 엔진이 예약 스캔 경로에서 저장+업로드를 끝냈다.
// --upload 만 주면 엔진은 아무것도 저장하지 않으므로 여기서 CSV를 env/에 쓰고 직접 올린다.
if (options.Upload && !options.Scheduled && saved != null)
    await UploadResultsAsync(services, saved, results, config.GetSystemName());

if (options.Output == OutputFormat.Pdf)
{
    if (options.OutFile == null) { Console.Error.WriteLine("error: -o pdf requires --out <file>"); return 2; }
    await KetworkScanner.Reports.PdfReport.SaveAsync(options.OutFile, results, config.GetSystemName(), ts);
    Console.Error.WriteLine($"info: wrote PDF report to {options.OutFile}");
    services.History?.Dispose();
    return results.Any(i => i.HasProhibitedPort) ? 3 : 0;
}

string rendered = options.Output switch
{
    OutputFormat.Json => ReportGenerator.BuildJson(results, config.GetSystemName(), ts),
    // GUI/예약 스캔과 같은 열 구성이라 GUI의 "불러오기"와 수집 서버가 그대로 읽을 수 있다.
    OutputFormat.Csv => ScanEngine.BuildCsv(results),
    OutputFormat.Html => ReportGenerator.BuildHtml(results, config.GetSystemName(), ts),
    _ => TableRenderer.Render(results),
};

if (options.OutFile != null)
{
    File.WriteAllText(options.OutFile, rendered, new UTF8Encoding(false));
    Console.Error.WriteLine($"info: wrote {results.Count(i => i.Alive)} alive host(s) to {options.OutFile}");
}
else
{
    Console.Out.WriteLine(rendered);
}

services.History?.Dispose();
// 위험 포트가 발견되면 종료 코드 3으로 알려 스크립트/모니터링이 감지할 수 있게 한다.
return results.Any(i => i.HasProhibitedPort) ? 3 : 0;

static string SafeHostName()
{
    try { return Dns.GetHostName(); } catch { return "netscan"; }
}

// 결과 CSV를 엔진과 같은 이름 규칙(<system>_yyyyMMdd_HHmmss.csv)으로 env/에 저장한 뒤 업로드 창구(즉시 전송, 실패 시 outbox)로 보낸다.
static async Task UploadResultsAsync(ScanServices services, AppSettingsData saved, IReadOnlyList<IPInfo> results, string systemName)
{
    if (!saved.Upload.Enabled)
    {
        Console.Error.WriteLine("warn: --upload given but result upload is disabled in settings.json; nothing uploaded.");
        return;
    }
    if (services.Uploader == null)
    {
        Console.Error.WriteLine("warn: upload service unavailable; nothing uploaded.");
        return;
    }
    if (results.Count == 0)
    {
        Console.Error.WriteLine("warn: no results to upload.");
        return;
    }

    string fileName;
    string fullPath;
    try
    {
        string dir = ScanEngine.GetEnvDirectory();
        Directory.CreateDirectory(dir);
        fileName = $"{ScanEngine.SanitizeFileNameComponent(systemName)}{DateTime.Now:_yyyyMMdd_HHmmss}.csv";
        fullPath = Path.Combine(dir, fileName);
        await File.WriteAllTextAsync(fullPath, ScanEngine.BuildCsv(results), new UTF8Encoding(false));
        Console.Error.WriteLine($"info: saved {fullPath}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("error: could not save result CSV for upload: " + ex.Message);
        return;
    }

    try
    {
        bool sent = await services.Uploader.UploadAsync(fullPath, saved.Upload, m => Console.Error.WriteLine("upload: " + m), CancellationToken.None);
        if (sent)
            Console.Error.WriteLine($"info: uploaded {fileName} ({saved.Upload.Protocol} → {saved.Upload.Host})");
        else
            Console.Error.WriteLine($"warn: upload of {fileName} failed; queued in outbox ({services.Uploader.Outbox.Count} pending), retried on the next upload");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine("error: upload failed: " + ex.Message);
    }
}

// stdin에서 y/N 확인을 받는다. -y 로 건너뛸 수 있다.
static bool Confirm(string prompt)
{
    Console.Error.Write(prompt + " [y/N] ");
    string? answer = Console.ReadLine();
    return string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase);
}

// netscan history [scans|inventory|host <ip>|prune <days>]
static int RunHistory(CliOptions o)
{
    using var store = new ScanHistoryStore(ScanHistoryStore.DefaultPath);
    switch (o.HistorySub)
    {
        case "inventory":
        {
            var rows = store.GetInventory();
            if (o.Output == OutputFormat.Json)
            {
                Console.Out.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            Console.Out.WriteLine($"{"IP",-16} {"FirstSeen",-20} {"LastSeen",-20} {"Alive",-5} {"Seen",4}  {"MAC",-18} {"Name",-24} Ports");
            foreach (var r in rows)
                Console.Out.WriteLine($"{r.Ip,-16} {r.FirstSeen.LocalDateTime,-20:yyyy-MM-dd HH:mm:ss} {r.LastSeen.LocalDateTime,-20:yyyy-MM-dd HH:mm:ss} {(r.LastAlive ? "yes" : "no"),-5} {r.SeenCount,4}  {r.LastMac,-18} {Trunc(r.LastName, 24),-24} {r.LastPorts}");
            return 0;
        }
        case "host":
        {
            if (string.IsNullOrEmpty(o.HistoryArg)) { Console.Error.WriteLine("error: history host <ip>"); return 2; }
            var rows = store.GetHostHistory(o.HistoryArg);
            if (o.Output == OutputFormat.Json)
            {
                Console.Out.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            Console.Out.WriteLine($"{"Scan",6} {"StartedAt",-20} {"Alive",-5} {"MAC",-18} {"Risky",-5} Ports / Service");
            foreach (var r in rows)
                Console.Out.WriteLine($"{r.ScanId,6} {r.StartedAt.LocalDateTime,-20:yyyy-MM-dd HH:mm:ss} {(r.Alive ? "yes" : "no"),-5} {r.Mac,-18} {(r.HasProhibited ? "YES" : ""),-5} {r.Ports} {r.Service}");
            return 0;
        }
        case "prune":
        {
            int days = int.TryParse(o.HistoryArg, out int d) && d > 0 ? d : 90;
            int removed = store.Prune(DateTimeOffset.UtcNow.AddDays(-days));
            Console.Error.WriteLine($"info: removed {removed} scan(s) older than {days} days");
            return 0;
        }
        default:
        {
            var rows = store.ListScans(o.HistoryLimit);
            if (o.Output == OutputFormat.Json)
            {
                Console.Out.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            Console.Out.WriteLine($"{"Id",6} {"StartedAt",-20} {"FinishedAt",-20} {"System",-16} {"Total",5} {"Alive",5} {"Risky",5} Sched");
            foreach (var r in rows)
                Console.Out.WriteLine($"{r.Id,6} {r.StartedAt.LocalDateTime,-20:yyyy-MM-dd HH:mm:ss} {r.FinishedAt.LocalDateTime,-20:yyyy-MM-dd HH:mm:ss} {Trunc(r.SystemName, 16),-16} {r.Total,5} {r.Alive,5} {r.Prohibited,5} {(r.Scheduled ? "yes" : "")}");
            return 0;
        }
    }
}

static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n - 1) + "…";

// netscan assets [list|approve|unapprove|set|delete]
static int RunAssets(CliOptions o)
{
    using var store = new ScanHistoryStore(ScanHistoryStore.DefaultPath);
    var now = DateTimeOffset.UtcNow;
    switch (o.Sub)
    {
        case "approve":
        case "unapprove":
        {
            bool approve = o.Sub == "approve";
            if (!o.All && o.Args.Count == 0) { Console.Error.WriteLine($"error: assets {o.Sub} <ip…> | --all"); return 2; }
            IEnumerable<string> ips = o.All
                ? store.GetInventory().Where(h => h.LastAlive).Select(h => h.Ip)
                : o.Args;
            int n = store.SetApproved(ips, approve, now);
            Console.Error.WriteLine($"info: {n} host(s) {(approve ? "approved" : "unapproved")}");
            return 0;
        }
        case "set":
        {
            if (o.Args.Count == 0) { Console.Error.WriteLine("error: assets set <ip> --owner X --tags a,b --note N"); return 2; }
            if (o.Owner == null && o.Tags == null && o.Note == null)
            {
                Console.Error.WriteLine("error: assets set needs at least one of --owner, --tags, --note");
                return 1;
            }
            if (!store.SetHostMeta(o.Args[0], o.Owner, o.Tags, o.Note))
            {
                Console.Error.WriteLine($"error: could not update host {o.Args[0]}");
                return 1;
            }
            Console.Error.WriteLine($"info: updated {o.Args[0]}");
            return 0;
        }
        case "delete":
        {
            if (o.Args.Count == 0) { Console.Error.WriteLine("error: assets delete <ip…> [-y]"); return 2; }
            if (!o.Yes && !Confirm($"delete {string.Join(", ", o.Args)} from the inventory (scan history is kept)?"))
            {
                Console.Error.WriteLine("info: cancelled");
                return 1;
            }
            int deleted = 0;
            foreach (string ip in o.Args)
            {
                if (store.DeleteHost(ip)) deleted++;
                else Console.Error.WriteLine($"warn: host {ip} not found in inventory");
            }
            Console.Error.WriteLine($"info: {deleted} host(s) deleted");
            return deleted == o.Args.Count ? 0 : 1;
        }
        default:
        {
            var rows = store.GetInventory();
            if (o.Output == OutputFormat.Json)
            {
                Console.Out.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            Console.Out.WriteLine($"{"IP",-16} {"Appr",-4} {"Alive",-5} {"Risk",4} {"Owner",-14} {"Tags",-16} {"MAC",-18} {"Approved MAC",-18} Name");
            foreach (var r in rows)
                Console.Out.WriteLine($"{r.Ip,-16} {(r.Approved ? "yes" : "no"),-4} {(r.LastAlive ? "yes" : "no"),-5} {r.RiskScore,4} {Trunc(r.Owner, 14),-14} {Trunc(r.Tags, 16),-16} {r.LastMac,-18} {r.ApprovedMac,-18} {Trunc(r.LastName, 24)}");
            return 0;
        }
    }
}

// netscan alerts [list|ack|snooze|reopen]
static int RunAlerts(CliOptions o)
{
    using var store = new ScanHistoryStore(ScanHistoryStore.DefaultPath);
    switch (o.Sub)
    {
        case "ack":
        case "reopen":
        case "snooze":
        {
            if (o.Args.Count == 0 || !long.TryParse(o.Args[0], out long id)) { Console.Error.WriteLine("error: alerts " + o.Sub + " <id>"); return 2; }
            AlertState state = o.Sub switch { "ack" => AlertState.Acknowledged, "snooze" => AlertState.Snoozed, _ => AlertState.Open };
            DateTimeOffset? until = null;
            if (state == AlertState.Snoozed)
                until = DateTimeOffset.UtcNow.AddHours(o.Args.Count > 1 && double.TryParse(o.Args[1], NumberStyles.Float, CultureInfo.InvariantCulture, out double h) ? h : 24);
            bool ok = store.SetAlertState(id, state, until, o.Note);
            Console.Error.WriteLine(ok ? $"info: alert {id} → {state}" : $"error: alert {id} not found");
            return ok ? 0 : 1;
        }
        default:
        {
            var rows = store.ListAlerts(includeResolved: o.All);
            if (o.Output == OutputFormat.Json)
            {
                Console.Out.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            Console.Out.WriteLine($"{"Id",5} {"State",-12} {"Type",-20} {"IP",-16} {"First",-17} {"Last",-17} {"N",3}  Detail");
            foreach (var a in rows)
                Console.Out.WriteLine($"{a.Id,5} {a.State,-12} {a.Type,-20} {a.Ip,-16} {a.FirstSeen.LocalDateTime,-17:yyyy-MM-dd HH:mm} {a.LastSeen.LocalDateTime,-17:yyyy-MM-dd HH:mm} {a.Count,3}  {Trunc(a.Detail, 40)}");
            return 0;
        }
    }
}

static int RunSettings(CliOptions o)
{
    if (o.Args.Count == 0) { Console.Error.WriteLine("error: settings export <file> | import <file>"); return 2; }
    try
    {
        if (o.Sub == "export") { AppSettingsStore.Export(o.Args[0]); Console.Error.WriteLine("info: exported to " + o.Args[0]); return 0; }
        if (o.Sub == "import") { AppSettingsStore.Import(o.Args[0]); Console.Error.WriteLine("info: imported " + o.Args[0]); return 0; }
    }
    catch (Exception ex) { Console.Error.WriteLine("error: " + ex.Message); return 1; }
    Console.Error.WriteLine("error: settings export <file> | import <file>");
    return 2;
}

static KetworkScanner.Updates.ReferenceDataUpdater CreateRefDataUpdater(AppSettingsData s)
    => new(string.IsNullOrWhiteSpace(s.ReferenceData.SourceUrl)
        ? KetworkScanner.Updates.ReferenceDataUpdater.DefaultSourceUrl(s.Update.Repository)
        : s.ReferenceData.SourceUrl);

// netscan refdata [check|update] — 저장소의 data/refdata.json과 비교해 참고 포트 목록·OUI·취약점 규칙을 사용자 폴더에 내려받는다.
// check: 현재 버전과 원격 버전만 출력(변경 없음). update(기본): 새 파일을 내려받아 적용. 종료 코드 10 = check에서 새 데이터 있음.
static async Task<int> RunRefDataAsync(CliOptions o)
{
    AppSettingsData settings;
    try { settings = AppSettingsStore.LoadSettings(); } catch { settings = new AppSettingsData(); }
    var updater = CreateRefDataUpdater(settings);
    Console.Error.WriteLine("info: source " + updater.SourceUrl);
    Console.Error.WriteLine("info: " + KetworkScanner.Updates.ReferenceDataUpdater.Describe());
    try
    {
        if (o.Sub == "check")
        {
            using var http = KetworkScanner.Updates.GitHubReleases.CreateClient();
            string json = await http.GetStringAsync(updater.SourceUrl + KetworkScanner.Updates.ReferenceDataUpdater.ManifestFileName);
            var remote = KetworkScanner.Updates.ReferenceManifest.Parse(json);
            if (remote == null) { Console.Error.WriteLine("error: invalid manifest"); return 1; }
            var current = KetworkScanner.Updates.ReferenceDataUpdater.EffectiveVersions().ToDictionary(f => f.Name, f => f, StringComparer.OrdinalIgnoreCase);
            int newer = 0;
            foreach (var f in remote.Files)
            {
                current.TryGetValue(f.Name, out var cur);
                bool isNew = cur == null || !string.Equals(cur.Sha256, f.Sha256, StringComparison.OrdinalIgnoreCase) && string.CompareOrdinal(f.Version, cur.Version) >= 0;
                if (isNew) newer++;
                Console.WriteLine($"{f.Name,-20} local {cur?.Version ?? "-",-10} remote {f.Version,-10} {(isNew ? "NEW" : "ok")}");
            }
            return newer > 0 ? 10 : 0;
        }

        var result = await updater.CheckAndUpdateAsync(force: true, TimeSpan.Zero, CancellationToken.None);
        if (result.Error != null) { Console.Error.WriteLine("error: " + result.Error); return 1; }
        foreach (string skip in result.Skipped) Console.Error.WriteLine("warn: " + skip);
        if (result.Changed) Console.Error.WriteLine("info: updated " + string.Join(", ", result.Updated.Select(f => f.Name + " " + f.Version)));
        else Console.Error.WriteLine("info: reference data is up to date");
        return result.Skipped.Count > 0 ? 1 : 0;
    }
    catch (Exception ex) { Console.Error.WriteLine("error: " + ex.Message); return 1; }
}

// netscan update [check|apply] — 현재 RID용 압축본을 받아 SHA256SUMS.txt로 검증한 뒤 설치 폴더에 적용한다.
static async Task<int> RunUpdateAsync(CliOptions o)
{
    // 설정의 Update.Repository(포크/사내 미러)가 있으면 그 저장소의 릴리스를 본다.
    string? repo = null;
    try { repo = AppSettingsStore.LoadSettings().Update.Repository; } catch { }
    var updater = new KetworkScanner.Updates.HeadlessUpdater(new KetworkScanner.Updates.GitHubReleases(repo));
    var current = KetworkScanner.Updates.GitHubReleases.CurrentVersion();
    try
    {
        var found = await updater.CheckAsync(current, o.Beta, CancellationToken.None);
        if (found == null) { Console.Error.WriteLine($"info: up to date (v{current.ToString(3)})"); return 0; }
        Console.Error.WriteLine($"info: v{found.Version.ToString(3)} available ({found.Archive.Name}, {found.Archive.Size / 1024 / 1024} MB){(found.ExpectedSha256 == null ? " - no checksum published" : "")}");
        if (o.Sub == "check") return 10;
        if (!o.Yes && !Confirm("apply update now?")) return 1;
        string stage = await updater.DownloadAndStageAsync(found, requireChecksum: true,
            p => { if (!Console.IsErrorRedirected) Console.Error.Write($"\rdownloading {p}%   "); }, CancellationToken.None);
        Console.Error.WriteLine();
        string install = KetworkScanner.Updates.HeadlessUpdater.InstallDirectory;
        if (OperatingSystem.IsWindows())
        {
            KetworkScanner.Updates.HeadlessUpdater.LaunchWindowsApplyHelper(stage, install, null);
            Console.Error.WriteLine("info: update will be applied as soon as this process exits.");
        }
        else
        {
            int n = KetworkScanner.Updates.HeadlessUpdater.ApplyInPlace(stage, install);
            Console.Error.WriteLine($"info: updated {n} file(s) in {install}; new version takes effect on the next run.");
        }
        return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine("error: " + ex.Message); return 1; }
}

static int RunDiag(CliOptions o)
{
    try
    {
        using var store = File.Exists(ScanHistoryStore.DefaultPath) ? new ScanHistoryStore(ScanHistoryStore.DefaultPath) : null;
        string zip = KetworkScanner.Support.DiagnosticBundle.Create(o.Sub.Length > 0 ? o.Sub : null, history: store);
        Console.Out.WriteLine(zip);
        return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine("error: " + ex.Message); return 1; }
}
