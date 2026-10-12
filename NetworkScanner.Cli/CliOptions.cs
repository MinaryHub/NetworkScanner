using NetworkScanner;

namespace NetworkScanner.Cli;

internal enum OutputFormat { Table, Json, Csv, Html, Pdf }
internal enum CliCommand { Scan, History, Assets, Alerts, Settings, Diag, Update }

// 명령행 옵션 파서. 최소한의 GNU 스타일 --옵션만 다룬다.
internal sealed class CliOptions
{
    public CliCommand Command { get; private set; } = CliCommand.Scan;
    public string HistorySub { get; private set; } = "scans";   // scans|inventory|host|prune
    public string? HistoryArg { get; private set; }
    public string Sub { get; private set; } = "";               // assets/alerts/settings 하위 명령
    public List<string> Args { get; } = new();                   // 하위 명령 위치 인자
    public string? Owner { get; private set; }
    public string? Tags { get; private set; }
    public string? Note { get; private set; }
    public bool All { get; private set; }
    public string? Profile { get; private set; }
    public bool PdfNeedsFile { get; set; }
    public bool Yes { get; private set; }
    public bool NoDiscovery { get; private set; }
    public bool Beta { get; private set; }
    public int HistoryLimit { get; private set; } = 50;

    public List<ScanRangeInfo> Ranges { get; } = new();
    public string Ports { get; private set; } = "";      // "22/80/443" 형식(내부), 미지정 시 ""
    public bool PortsSet { get; private set; }
    public OutputFormat Output { get; private set; } = OutputFormat.Table;
    public string? OutFile { get; private set; }
    public string? SystemName { get; private set; }
    public string Language { get; private set; } = Localization.English;
    public bool LanguageSet { get; private set; }
    public bool Quiet { get; private set; }
    public bool NoHistory { get; private set; }
    public bool UseSettings { get; private set; }
    public bool Upload { get; private set; }
    public bool Notify { get; private set; }
    public bool Scheduled { get; private set; }
    public int Parallelism { get; private set; }
    public List<string> Allow { get; } = new();
    public bool ShowHelp { get; private set; }
    public string? Error { get; private set; }

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        int start = 0;
        if (args.Length > 0 && args[0] is "assets" or "alerts" or "settings" or "diag" or "update")
        {
            o.Command = args[0] switch { "assets" => CliCommand.Assets, "alerts" => CliCommand.Alerts, "settings" => CliCommand.Settings, "update" => CliCommand.Update, _ => CliCommand.Diag };
            start = 1;
            if (args.Length > 1 && !args[1].StartsWith('-')) { o.Sub = args[1]; start = 2; }
            while (start < args.Length && !args[start].StartsWith('-')) o.Args.Add(args[start++]);
        }
        else if (args.Length > 0 && args[0] == "history")
        {
            o.Command = CliCommand.History;
            start = 1;
            if (args.Length > 1 && !args[1].StartsWith('-'))
            {
                o.HistorySub = args[1];
                start = 2;
                if (o.HistorySub is "host" or "prune")
                {
                    if (args.Length > 2 && !args[2].StartsWith('-')) { o.HistoryArg = args[2]; start = 3; }
                }
                else if (o.HistorySub is not ("scans" or "inventory"))
                {
                    return o.Fail($"unknown history subcommand: {o.HistorySub} (scans|inventory|host <ip>|prune <days>)");
                }
            }
        }

        for (int i = start; i < args.Length; i++)
        {
            string a = args[i];
            string? Next() => i + 1 < args.Length ? args[++i] : null;

            switch (a)
            {
                case "-h":
                case "--help":
                    o.ShowHelp = true;
                    return o;

                case "--range":
                {
                    string? v = Next();
                    if (v == null) return o.Fail("--range requires a value (CIDR or start-end)");
                    if (!TryParseRange(v, out var r)) return o.Fail($"invalid --range: {v}");
                    o.Ranges.Add(r);
                    break;
                }

                case "--ports":
                {
                    string? v = Next();
                    if (v == null) return o.Fail("--ports requires a value (e.g. 22,80,443)");
                    // 쉼표/슬래시 모두 허용하고 내부 형식(슬래시 구분)으로 정규화한다.
                    var nums = v.Split(new[] { ',', '/', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                                .Where(t => int.TryParse(t, out _));
                    o.Ports = string.Join("/", nums);
                    o.PortsSet = true;
                    break;
                }

                case "--output":
                case "-o":
                {
                    string? v = Next()?.ToLowerInvariant();
                    o.Output = v switch
                    {
                        "table" => OutputFormat.Table,
                        "json" => OutputFormat.Json,
                        "csv" => OutputFormat.Csv,
                        "html" => OutputFormat.Html,
                        "pdf" => OutputFormat.Pdf,
                        _ => OutputFormat.Table,
                    };
                    if (v is not ("table" or "json" or "csv" or "html" or "pdf")) return o.Fail($"invalid --output: {v} (table|json|csv|html|pdf)");
                    if (v == "pdf" && o.OutFile == null) o.PdfNeedsFile = true;
                    break;
                }

                case "--out":
                {
                    o.OutFile = Next();
                    if (o.OutFile == null) return o.Fail("--out requires a file path");
                    break;
                }

                case "--system-name":
                    o.SystemName = Next();
                    break;

                case "--lang":
                {
                    string? v = Next()?.ToLowerInvariant();
                    if (v is not ("en" or "ko")) return o.Fail("--lang must be 'en' or 'ko'");
                    o.Language = v!;
                    o.LanguageSet = true;
                    break;
                }

                case "--limit":
                {
                    if (!int.TryParse(Next(), out int n) || n <= 0) return o.Fail("--limit requires a positive number");
                    o.HistoryLimit = n;
                    break;
                }

                case "--parallelism":
                {
                    if (!int.TryParse(Next(), out int n) || n <= 0 || n > 512) return o.Fail("--parallelism must be 1-512");
                    o.Parallelism = n;
                    break;
                }

                case "--allow":
                {
                    string? v = Next();
                    if (v == null) return o.Fail("--allow requires a value (port | ip:port | ip | cidr:port)");
                    var (valid, invalid) = RiskPolicy.ParseAllowList(v);
                    if (invalid.Count > 0) return o.Fail("invalid --allow entries: " + string.Join(", ", invalid));
                    o.Allow.AddRange(valid);
                    break;
                }

                case "--use-settings":
                    o.UseSettings = true;
                    break;

                case "--profile":
                {
                    string? v = Next()?.ToLowerInvariant();
                    if (v is not ("quick" or "standard" or "thorough")) return o.Fail("--profile must be quick|standard|thorough");
                    o.Profile = v;
                    break;
                }

                case "--owner": o.Owner = Next() ?? ""; break;
                case "--tags": o.Tags = Next() ?? ""; break;
                case "--note": o.Note = Next() ?? ""; break;
                case "--all": o.All = true; break;
                case "--yes": case "-y": o.Yes = true; break;
                case "--beta": o.Beta = true; break;

                case "--upload":
                    o.Upload = true;
                    o.UseSettings = true;
                    break;

                case "--notify":
                    o.Notify = true;
                    o.UseSettings = true;
                    break;

                case "--scheduled":
                    o.Scheduled = true;
                    break;

                case "--quiet":
                case "-q":
                    o.Quiet = true;
                    break;

                case "--no-history":
                    o.NoHistory = true;
                    break;

                case "--no-discovery":
                    o.NoDiscovery = true;
                    break;

                default:
                    return o.Fail($"unknown option: {a}");
            }
        }
        return o;
    }

    private CliOptions Fail(string message)
    {
        Error = message;
        return this;
    }

    // "192.168.1.0/24"(CIDR) 또는 "192.168.1.10-192.168.1.50"(범위) 형식을 파싱한다.
    private static bool TryParseRange(string value, out ScanRangeInfo range)
    {
        range = new ScanRangeInfo { Index = 0, StartIP = "", EndIP = "", Description = "cli" };

        if (value.Contains('/'))
        {
            if (!IPRangeUtil.TryParseCidr(value, out string s, out string e)) return false;
            range.StartIP = s;
            range.EndIP = e;
            return true;
        }

        if (value.Contains('-'))
        {
            string[] parts = value.Split('-', 2);
            if (!System.Net.IPAddress.TryParse(parts[0].Trim(), out _) ||
                !System.Net.IPAddress.TryParse(parts[1].Trim(), out _)) return false;
            range.StartIP = parts[0].Trim();
            range.EndIP = parts[1].Trim();
            return true;
        }

        // 단일 IP
        if (!System.Net.IPAddress.TryParse(value.Trim(), out _)) return false;
        range.StartIP = value.Trim();
        range.EndIP = value.Trim();
        return true;
    }

    public static void PrintHelp()
    {
        Console.WriteLine(
@"netscan - NetworkScanner command-line interface

USAGE:
  netscan [options]                          scan
  netscan history [scans|inventory|host <ip>|prune <days>] [--limit N] [-o json]
  netscan assets [list|approve <ip…>|unapprove <ip…>|set <ip> --owner X --tags a,b --note N] [--all]
  netscan alerts [list|ack <id>|snooze <id> [hours]|reopen <id>] [-o json]
  netscan settings [export <file>|import <file>]
  netscan diag [<zip path>]                  create a support/diagnostic bundle
  netscan update [check|apply] [--beta] [-y]  self-update the headless binaries from GitHub Releases

SCAN OPTIONS:
  --range <CIDR|start-end|ip>   Range to scan (repeatable). Examples:
                                  --range 192.168.1.0/24
                                  --range 10.0.0.1-10.0.0.50
                                If omitted, saved settings (--use-settings) or the
                                local subnet are used.
  --ports <list>                Ports to scan, e.g. --ports 22,80,443
                                (omit to skip port scanning)
  --use-settings                Use the GUI's settings.json (ranges, ports, limits, language)
  --upload                      Upload results using the saved upload settings (implies --use-settings)
  --notify                      Send change notifications using the saved settings (implies --use-settings)
  --scheduled                   Behave like a scheduled scan: save CSV + HTML report to the
                                user data folder (and upload when --upload)
  --parallelism <1-512>         Hosts scanned concurrently (default: 64 or saved setting)
  --profile quick|standard|thorough  Scan profile (quick: ping only; thorough: top ports, identity, vuln)
  --allow <list>                Risky-port exceptions: port | ip:port | ip | cidr:port (repeatable)
  -o, --output <table|json|csv|html|pdf>  Output format (default: table; pdf requires --out)
  --out <file>                  Write output to a file instead of stdout
  --system-name <name>          System name recorded with results (default: saved or hostname)
  --lang <en|ko>                Language for messages/labels (default: en)
  --no-history                  Do not record this scan in the local history database
  --no-discovery                Skip deep discovery (SSDP/mDNS/SMB/SSH/HTTP/UDP/SNMP tables)
  -q, --quiet                   Suppress progress messages on stderr
  -h, --help                    Show this help

EXIT CODES:
  0 ok, 1 scan error, 2 bad arguments, 3 ok but risky (backdoor) ports were found

NOTES:
  Progress is written to stderr; final results to stdout (safe to pipe).
  Reserved/backdoor port matching and vendor/OS/service detection are
  always applied to discovered hosts. Every scan is recorded in history.db
  under the user data folder unless --no-history is given.

EXAMPLES:
  netscan --range 192.168.1.0/24 --ports 22,80,443
  netscan --use-settings --scheduled --upload --notify -q     # cron/service style run
  netscan history inventory
  netscan history host 192.168.1.10 -o json");
    }
}
