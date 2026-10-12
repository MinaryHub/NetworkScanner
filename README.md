# NetworkScanner

A cross-platform network inventory and security scanner. It pings an IP range, records each live host's open TCP ports, MAC address / vendor, host name and service banner, flags ports commonly used by backdoors, detects changes between scans (new/offline hosts, MAC changes, newly opened or risky ports), keeps a local scan history, and can save, upload and alert on the results on a schedule.

It ships as:

| Front-end | Binary | Platforms |
|---|---|---|
| GUI ([Avalonia](https://avaloniaui.net)) | `NetworkScanner.Avalonia` | Windows x64/arm64, macOS arm64/x64, Linux x64/arm64 |
| CLI | `netscan` | same, plus a Docker image |
| Headless scheduler | `netscan-service` | Windows Service, systemd, launchd, foreground |

All three share one engine, `NetworkScanner.Core`. The UI is available in English (default) and Korean; the in-app user guide also has Japanese and Chinese.

## Download

Grab the file for your OS from the **[Releases page](../../releases/latest)**.

| OS | GUI | Headless (CLI + service) |
|---|---|---|
| Windows x64 / arm64 | `NetworkScanner-win-Setup.exe` / `NetworkScanner-win-arm64-Setup.exe` (or the `-Portable.zip`) | `netscan-<ver>-win-x64.zip`, `…-win-arm64.zip` |
| macOS Apple Silicon / Intel | `NetworkScanner-osx-Setup.pkg` / `NetworkScanner-osx-x64-Setup.pkg` | `netscan-<ver>-osx-arm64.tar.gz`, `…-osx-x64.tar.gz` |
| Linux x64 / arm64 | `NetworkScanner-linux.AppImage` / `NetworkScanner-linux-arm64.AppImage` | `netscan-<ver>-linux-x64.tar.gz`, `…-linux-arm64.tar.gz` |
| Docker | — | `ghcr.io/<owner>/netscan:<ver>` |

The `*.nupkg`, `RELEASES*`, `assets.*.json` and `releases.*.json` files are Velopack's auto-update feed; you don't need them.

> Installers are unsigned unless the repository owner has configured code-signing secrets (see [Releases](#releases)). Unsigned builds trigger Gatekeeper / SmartScreen warnings and occasional antivirus false positives; see [Known limitations](#known-limitations).

## Features

- Two-phase range scan: parallel ping sweep with TCP fallback for hosts that block ICMP, then per-host enrichment (MAC/vendor, reverse DNS, open ports, service banner, OS guess from TTL, device-type guess)
- Native ARP table lookup on every OS (no `arp` command required)
- Reserved-port and risky (backdoor/trojan) port matching
- Change detection between scans with security alerts; the previous scan is remembered across restarts
- SQLite scan history: past scans, per-host timeline, device inventory with first/last seen
- CSV (RFC 4180) save/load, HTML/JSON reports
- Result upload over **FTPS**, **SFTP** or **HTTPS** with certificate / host-key fingerprint pinning and an automatic retry outbox
- Notifications on detected changes: webhook (Slack/Teams/Discord…), syslog, SMTP
- Hourly scheduling and continuous monitoring, in the GUI or as a background service
- Secrets stored in the OS credential store (DPAPI / Keychain / libsecret) or an AES-256-GCM encrypted file — never in plain text
- CIDR range input, per-column sort, search / alive-only filter, Wake-on-LAN, in-app updates

## Project structure

| Path | Description |
|---|---|
| `NetworkScanner.Core/` | Engine and all shared logic (`net10.0`, no UI dependency) |
| `NetworkScanner.Avalonia/` | GUI |
| `NetworkScanner.Cli/` | `netscan` command-line front-end |
| `NetworkScanner.Service/` | `netscan-service` headless scheduler (Microsoft.Extensions.Hosting worker) |
| `NetworkScanner.Tests/` | xUnit tests for Core (run on every OS, no real network needed) |
| `data/` | Bundled reference data: `ouiinfo.ini` (IEEE OUI registry), `reservedports.ini`, `prohibitports.ini` |
| `assets/` | App icon (`icon/*.svg` masters → `app.ico` / `app.icns` / `app.png` via `tools/build-icons.sh`), bundled fonts and toolbar images |
| `deploy/` | systemd unit, launchd plist, Windows service installer script, Dockerfile |
| `tools/update-oui.sh` | Refreshes `data/ouiinfo.ini` from IEEE |

Inside Core: `ScanEngine` (scan flow), `ScanServices` (pluggable `IPinger` / `IPortProber` / `IArpResolver` / `IHostNameResolver` / uploader / history), `Platform/` (native ARP readers), `Secrets/` (credential stores), `Upload/` (FTPS/SFTP/HTTPS + outbox), `History/` (SQLite), `Notifications/`, `AppSettingsStore` (`settings.json`), `CsvCodec`, `Localization`.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) to build. Release packages are self-contained and need no runtime.
- Every project builds and runs on Windows, macOS and Linux; CI verifies all three.

## Build and run

```bash
dotnet build NetworkScanner.sln                        # whole solution, any OS
dotnet run --project NetworkScanner.Avalonia           # GUI
dotnet run --project NetworkScanner.Cli -- --help      # CLI
dotnet run --project NetworkScanner.Service -- --run-once
dotnet test NetworkScanner.Tests/NetworkScanner.Tests.csproj
```

## Command-line interface (`netscan`)

```
netscan [options]                                         scan
netscan history [scans|inventory|host <ip>|prune <days>]  query the local history database

--range <CIDR|start-end|ip>   Range to scan (repeatable). Default: saved settings or the local subnet
--ports <list>                Ports to check, e.g. 22,80,443 (omit to skip port scanning)
--use-settings                Use the GUI's settings.json (ranges, ports, limits, language)
--upload / --notify           Upload results / send notifications with the saved settings
--scheduled                   Save CSV + HTML report like a scheduled scan (for cron)
-o table|json|csv|html        Output format; --out <file> writes it to a file
--profile quick|standard|thorough, --allow <risky-port exceptions>
--parallelism <1-512>, --system-name <name>, --lang en|ko, --no-history, -q

netscan assets [list|approve <ip…>|unapprove <ip…>|set <ip> --owner X --tags a,b] [--all]
netscan alerts [list|ack <id>|snooze <id> [hours]|reopen <id>]
netscan settings export|import <file>      netscan diag [zip]
netscan update [check|apply] [--beta] [-y]  # exit 10 = update available (check)
```

Progress goes to stderr, results to stdout (safe to pipe). Exit code 3 means the scan succeeded but risky ports were found.

```bash
netscan --range 192.168.1.0/24 --ports 22,80,443 -o json --out scan.json
netscan --use-settings --scheduled --upload --notify -q      # cron / task-scheduler style run
netscan history inventory
docker run --rm --net=host --cap-add=NET_RAW ghcr.io/<owner>/netscan --range 10.0.0.0/24
```

## Assets, alerts and assessment

- **Asset approval**: every host ever seen is in the inventory (History screen / `netscan assets list`). Approve the ones you know (`netscan assets approve 10.0.0.5` or `--all` for everything currently alive); the MAC seen at approval time is pinned. With *Alert on unapproved devices* enabled, any live host outside the approved list raises `UnapprovedHost`, and an approved IP answering with a different MAC raises `ApprovedMacMismatch`. The first scan can auto-approve everything it finds to form the baseline. Owner, tags and notes are kept per host.
- **Alert operations**: the same event is one alert no matter how many scans repeat it; acknowledge or snooze it (`netscan alerts ack <id>` / `snooze <id> [hours]`), define maintenance windows (`Mon-Fri 22:00-06:00; Sat,Sun`) during which nothing is sent, choose how often an open alert is re-sent, and alerts resolve themselves when the condition disappears.
- **Identification**: besides reverse DNS, live hosts are asked over SNMP v2c (sysDescr/sysName/sysObjectID, community configurable), mDNS and NetBIOS; the best name wins and OS/device hints replace the TTL guess.
- **Assessment**: open ports and banners are matched against the offline rule set `data/vulnrules.json` (vulnerable versions such as old OpenSSH/nginx/Apache, exposed databases/remote-admin ports, SSH-1, plain Telnet/FTP) and TLS endpoints are inspected (expired/expiring/self-signed certificates, TLS 1.0/1.1, weak RSA keys). Each host gets a 0–100 risk score; `HighRisk` alerts fire above the configured threshold. Update the rule file with your own entries — the embedded copy is used when the file is missing.
- **Scan profiles**: *quick* (ping sweep only, 128 parallel), *standard* (your settings), *thorough* (top ~80 service ports added, identification + assessment on, slower timeouts). `--profile` on the CLI.
- **Reports**: HTML, JSON and **PDF** (Korean-capable) from the GUI, `-o pdf --out file.pdf` on the CLI; scheduled scans save CSV + HTML + PDF.
- **Operations**: settings export/import (no secrets inside), diagnostic bundle (`netscan diag` or Settings) for support, history retention (days) with daily rotating backups and restore.
- **Automatic updates** (Settings → Updates): check every N hours, download in the background, install when the app closes or click *Restart now*; opt into pre-releases (beta). The headless binaries update themselves too: `netscan update` (or `netscan update check`), and `netscan-service` applies updates on its own when *Install automatically* is on — downloads are verified against the release's `SHA256SUMS.txt`, files are swapped in place on Linux/macOS (the service exits with code 75 so systemd/launchd restart it) and through a helper process on Windows (which restarts the service).

## Central collector (`netscan-collector`)

Several sites can report to one server: the collector (`NetworkScanner.Collector`, Docker image `ghcr.io/<owner>/netscan-collector`) accepts the scanners' HTTPS uploads (one Bearer token per site), stores CSV/HTML/PDF/JSON reports, parses the CSVs into per-scan summaries and host lists, and serves a dashboard (`/`, token login) plus a JSON API (`/api/sites`, `/api/sites/{site}/scans`, `/api/sites/{site}/scans/{id}/hosts`, `/api/uploads/{id}`). See [`deploy/README.md`](deploy/README.md#central-collector-netscan-collector) for configuration; put a TLS-terminating reverse proxy in front of it.

## Headless scheduler (`netscan-service`)

`netscan-service` reads the same `settings.json` as the GUI and runs the configured hourly schedule or continuous monitoring without a window — saving reports, uploading, notifying and recording history. If the machine was asleep at the top of the hour the scan still runs later in that hour. Install it with the files in [`deploy/`](deploy/README.md):

- Linux: `deploy/netscan.service` (systemd; grants `CAP_NET_RAW` so ping works without root)
- macOS: `deploy/kr.smic.netscan.plist` (launchd agent)
- Windows: `deploy/install-windows-service.ps1`
- Anywhere: `netscan-service --run-once` from cron / Task Scheduler

## Runtime configuration / data files

User data lives in a per-user folder that survives updates: `%APPDATA%\NetworkScanner` on Windows, `~/Library/Application Support/NetworkScanner` on macOS, `~/.config/NetworkScanner` on Linux. (Data an older macOS build left in `~/.config/NetworkScanner` is copied over on first start.)

| File | Purpose |
|---|---|
| `settings.json` | All settings and scan ranges (schema v2). Old `setting.ini` / `iprange.ini` are migrated once and renamed `*.migrated`. |
| `secrets/` | Encrypted-file secret store (used when no OS credential store is available). Passwords/tokens are never written to `settings.json`. |
| `history.db` | SQLite scan history, inventory (approvals/owners/tags) and alerts |
| `backups/` | Daily `history-*.db` backups (rotated) |
| `env/` | Saved CSV results and HTML reports |
| `outbox/` | Uploads waiting to be retried |
| `logs/` | Daily log files (14 days kept) |
| `annotations.ini`, `known_hosts` | Per-IP names/notes; pinned SFTP host keys |

The bundled reference files (`ouiinfo.ini`, `reservedports.ini`, `prohibitports.ini`) are resolved next to the executable.

## Upload and notifications

Settings → *Result upload*: choose FTPS (default), implicit FTPS, SFTP, HTTPS, or plain FTP (must be explicitly allowed; shown as insecure). Optionally pin the server's SHA-256 certificate / host-key fingerprint. For SFTP without a pin, the host key is remembered on first contact and any later change is rejected. HTTPS posts a multipart form (`name`, `file`) with a Bearer token to the configured URL.

Failed uploads are copied to `outbox/` and retried with exponential backoff (1 min → 24 h, up to 30 attempts) on every later upload, scheduled scan or service cycle.

Settings → *Notifications*: webhook URL (JSON `{"text": …}`), syslog host/port (UDP, RFC 5424) and/or SMTP. Choose whether to send all changes or only security-relevant ones (MAC changes, risky ports).

## Packaging for distribution

```bash
dotnet publish NetworkScanner.Avalonia/NetworkScanner.Avalonia.csproj -c Release -r osx-arm64 --self-contained true -o publish/osx-arm64
dotnet tool install -g vpk
vpk pack --packId NetworkScanner --packVersion 2.0.0 --packDir publish/osx-arm64 --mainExe NetworkScanner.Avalonia \
  --packTitle "Network Scanner" --packAuthors SMIC --runtime osx-arm64 --channel osx --outputDir release-packages/osx-arm64
```

`vpk` packages only for the OS it runs on. On Windows add `--mainExe NetworkScanner.Avalonia.exe --icon assets/app.ico`. Channels: `win`, `win-arm64`, `osx`, `osx-x64`, `linux`, `linux-arm64`.

## Releases

Pushing a `v*.*.*` tag runs `.github/workflows/release.yml`, which builds GUI installers for six RIDs, CLI + service archives, a multi-arch Docker image, and attaches everything to a GitHub Release. If these repository secrets exist the binaries are signed (and notarized on macOS): `WINDOWS_CERT_PFX_BASE64`, `WINDOWS_CERT_PASSWORD`, `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `MACOS_KEYCHAIN_PASSWORD`, `MACOS_SIGN_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`. `build-and-test.yml` runs the tests and the full build on Windows, macOS and Linux for every push, plus a vulnerable-package check and a Docker build.

## Known limitations

- **MAC addresses** are only resolvable inside the scanner's own subnet (ARP). Hosts behind a router show no MAC.
- **ICMP permission**: on Linux/macOS a normal user may be unable to send raw ICMP. The scan then relies on the TCP liveness fallback and logs a one-time hint. Fix: `sudo setcap cap_net_raw+ep <executable>` (the systemd unit already grants it) or run as root.
- **Unsigned installer warnings** when no signing secrets are configured: macOS → right-click → Open (or `xattr -d com.apple.quarantine <file>`); Windows SmartScreen → *More info → Run anyway*. Some antivirus products quarantine unsigned Velopack installers; use the Portable zip or whitelist it.
- IPv4 only.

## License

See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for bundled components. The license for NetworkScanner itself is defined by the repository owner (`LICENSE`).
