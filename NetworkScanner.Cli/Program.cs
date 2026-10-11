using System.Globalization;
using System.Net;
using System.Text;
using NetworkScanner;
using NetworkScanner.Cli;
using NetworkScanner.History;
using NetworkScanner.Notifications;

// 헤드리스/서버 환경에서 GUI 없이 대역을 스캔하는 CLI. NetworkScanner.Core의 ScanEngine을 그대로 구동한다.
// 진행 상황은 stderr로, 최종 결과는 stdout으로 내보내 파이프 연동(특히 JSON)이 깨지지 않게 한다.

Console.OutputEncoding = Encoding.UTF8;

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
PingTester.OnError = m => Console.Error.WriteLine("warn: " + m);
PortReferenceLoader.OnError = m => Console.Error.WriteLine("warn: " + m);
AppSettingsStore.OnError = m => Console.Error.WriteLine("warn: " + m);
AppLogger.Sink += (level, _, m) => { if (level >= NetworkScanner.LogLevel.Error) Console.Error.WriteLine("error: " + m); };

// --use-settings: GUI와 같은 settings.json(대역/포트/업로드/알림)을 그대로 사용한다. 명령행 옵션이 있으면 그것이 우선한다.
AppSettingsData? saved = options.UseSettings ? AppSettingsStore.LoadSettings() : null;
Localization.Current = options.LanguageSet ? options.Language : (saved?.Language ?? options.Language);

if (options.Command == CliCommand.History)
{
    return RunHistory(options);
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
    Upload = options.Upload && saved != null ? saved.Upload : new NetworkScanner.Upload.UploadSettings(),
};

var items = new IPInfoList();
var services = ScanServices.CreateDefault(withHistory: !options.NoHistory);
var engineOptions = saved != null ? ScanOptions.FromSettings(saved) : new ScanOptions();
if (options.Parallelism > 0) engineOptions.Parallelism = options.Parallelism;
var engine = new ScanEngine(items, oui, config, services, engineOptions);

bool quiet = options.Quiet || Console.IsErrorRedirected;
engine.Message += m => { if (!quiet) Console.Error.WriteLine(m); };
Notifier? notifier = options.Notify && saved != null ? new Notifier(saved.Notifications) : null;
engine.ScanChangesDetected += changes =>
{
    foreach (var c in changes)
        Console.Error.WriteLine("change: " + ScanDiff.Describe(c));
    if (notifier != null)
    {
        try { notifier.NotifyChangesAsync(config.GetSystemName(), changes, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (Exception ex) { Console.Error.WriteLine("warn: notify failed: " + ex.Message); }
    }
};

Console.CancelKeyPress += (_, e) => { e.Cancel = true; engine.ScanningStop(); };

engine.InitFromConfig();
// --scheduled: GUI의 예약 스캔과 동일하게 CSV/HTML 리포트를 env/에 남기고 업로드 설정이면 업로드한다(cron/서비스용).
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
string rendered = options.Output switch
{
    OutputFormat.Json => ReportGenerator.BuildJson(results, config.GetSystemName(), ts),
    OutputFormat.Csv => BuildCsv(results),
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

static string BuildCsv(IReadOnlyList<IPInfo> items)
{
    var sb = new StringBuilder();
    sb.AppendLine(CsvCodec.FormatLine(new[] { "IPAddress", "Status", "Name", "Type", "OS", "Ports", "Service", "MAC", "Vendor", "RTT" }));
    foreach (var i in items)
        sb.AppendLine(CsvCodec.FormatLine(new[]
        {
            i.Ip, i.StatusText, i.SystemName, i.DeviceType, i.OsGuess,
            i.Ports, i.Service, i.Macaddr, i.Vendor, i.RountTime
        }));
    return sb.ToString();
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
