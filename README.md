# KetworkScanner

A cross-platform network inventory and security scanner. It pings an IP range, records each live host's open TCP ports, MAC address / vendor, host name and service banner, flags ports commonly used by backdoors, detects changes between scans (new/offline hosts, MAC changes, newly opened or risky ports), keeps a local scan history, and can save, upload and alert on the results on a schedule.

It ships as:

| Front-end | Binary | Platforms |
|---|---|---|
| GUI ([Avalonia](https://avaloniaui.net)) | `KetworkScanner.Avalonia` | Windows x64/arm64, macOS arm64/x64, Linux x64/arm64 |
| CLI | `netscan` | same, plus a Docker image |
| Headless scheduler | `netscan-service` | Windows Service, systemd, launchd, foreground |

All three share one engine, `KetworkScanner.Core`. The UI is available in English (default) and Korean; the in-app user guide also has Japanese and Chinese.

## Download

Grab the file for your OS from the **[Releases page](../../releases/latest)**.

| OS | GUI | Headless (CLI + service) |
|---|---|---|
| Windows x64 / arm64 | `KetworkScanner-win-Setup.exe` / `KetworkScanner-win-arm64-Setup.exe` (or the `-Portable.zip`) | `netscan-<ver>-win-x64.zip`, `…-win-arm64.zip` |
| macOS Apple Silicon / Intel | `KetworkScanner-osx-Setup.pkg` / `KetworkScanner-osx-x64-Setup.pkg` | `netscan-<ver>-osx-arm64.tar.gz`, `…-osx-x64.tar.gz` |
| Linux x64 / arm64 | `KetworkScanner-linux.AppImage` / `KetworkScanner-linux-arm64.AppImage` | `netscan-<ver>-linux-x64.tar.gz`, `…-linux-arm64.tar.gz` |
| Docker | — | `ghcr.io/<owner>/netscan:<ver>` (CLI), `ghcr.io/<owner>/netscan-collector:<ver>` (collector) |

The `*.nupkg`, `RELEASES*`, `assets.*.json` and `releases.*.json` files are Velopack's auto-update feed; you don't need them.

> Installers are unsigned unless the repository owner has configured code-signing secrets (see [Releases](#releases)). Unsigned builds trigger Gatekeeper / SmartScreen warnings and occasional antivirus false positives; see [Known limitations](#known-limitations).

## Features

- Two-phase range scan: parallel ping sweep (adaptive retry) with TCP, ARP-cache and multicast/neighbour-table fallbacks for hosts that block ICMP, then per-host enrichment (MAC/vendor, reverse DNS, open ports, service banner, OS guess from TTL, device-type guess)
- Deep discovery: SMB/SSH/HTTP fingerprints (exact Windows build, Linux distribution, web UI model), SSDP/mDNS browsing (friendly name, model, Apple/Chromecast/printer details), UDP service probes, router SNMP ARP/FDB/LLDP tables (switch port per host), IPv6 neighbours, optional passive capture (DHCP/ARP/TCP fingerprints); every value carries its source and confidence
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
- Reference data (IANA port list, backdoor port list, IEEE OUI tables, vulnerability rules) refreshed automatically from the repository, verified by SHA-256

## Project structure

| Path | Description |
|---|---|
| `KetworkScanner.Core/` | Engine and all shared logic (`net10.0`, no UI dependency) |
| `KetworkScanner.Avalonia/` | GUI |
| `KetworkScanner.Cli/` | `netscan` command-line front-end |
| `KetworkScanner.Service/` | `netscan-service` headless scheduler (Microsoft.Extensions.Hosting worker) |
| `KetworkScanner.Collector/` | `netscan-collector` central report collector (ASP.NET Core minimal API + SQLite index + dashboard) |
| `KetworkScanner.Tests/` | xUnit tests for Core (run on every OS, no real network needed) |
| `KetworkScanner.Cli.Tests/` | xUnit tests for the CLI option parser and table renderer |
| `KetworkScanner.Collector.Tests/` | xUnit integration tests for the collector (in-memory test server) |
| `data/` | Bundled reference data: `ouiinfo.ini` / `ouiinfo-mam.ini` / `ouiinfo-mas.ini` (IEEE MA-L/MA-M/MA-S registries), `reservedports.ini`, `prohibitports.ini`, `vulnrules.json` (offline vulnerability rules) |
| `assets/` | App icon (`icon/*.svg` masters → `app.ico` / `app.icns` / `app.png` via `tools/build-icons.sh`), bundled fonts and toolbar images |
| `deploy/` | systemd unit, launchd plist, Windows service install/uninstall scripts, Dockerfiles for the CLI and the collector |
| `tools/update-oui.sh` | Refreshes `data/ouiinfo.ini` from IEEE |

Inside Core: `ScanEngine` (scan flow), `ScanServices` (pluggable `IPinger` / `IPortProber` / `IArpResolver` / `IHostNameResolver` / uploader / history), `Platform/` (native ARP readers), `Secrets/` (credential stores), `Upload/` (FTPS/SFTP/HTTPS + outbox), `History/` (SQLite), `Notifications/`, `AppSettingsStore` (`settings.json`), `CsvCodec`, `Localization`.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) to build. Release packages are self-contained and need no runtime.
- Every project builds and runs on Windows, macOS and Linux; CI verifies all three.

## Build and run

```bash
dotnet build KetworkScanner.sln                        # whole solution, any OS
dotnet run --project KetworkScanner.Avalonia           # GUI
dotnet run --project KetworkScanner.Cli -- --help      # CLI
dotnet run --project KetworkScanner.Service -- --run-once
dotnet test KetworkScanner.Tests/KetworkScanner.Tests.csproj
```

## Command-line interface (`netscan`)

```
netscan [options]                                         scan
netscan history [scans|inventory|host <ip>|prune <days>] [--limit N] [-o json]

--range <CIDR|start-end|ip>   IPv4 range to scan (repeatable). Default: saved settings or the local subnet
--ports <list>                Ports to check, e.g. 22,80,443 (omit to skip port scanning)
--use-settings                Use the GUI's settings.json (ranges, ports, limits, language); problems are warned
--upload / --notify           Upload the result CSV / send notifications with the saved settings
                              (--upload alone saves the CSV to env/ and uploads it; failures go to the outbox)
--scheduled                   Save CSV + HTML + PDF reports like a scheduled scan (for cron)
-o table|json|csv|html|pdf    Output format (csv = the GUI's column layout; pdf needs --out); --out <file> writes to a file
--profile quick|standard|thorough   quick = short timeouts, no banners/identity/vuln/deep discovery; thorough = top ports + everything
--parallelism <1-512>         Concurrent hosts (overrides the profile), --allow <risky-port exceptions>
--system-name <name>, --lang en|ko, --no-history, --no-discovery, -q

netscan assets [list|approve <ip…>|unapprove <ip…>|set <ip> --owner X --tags a,b --note N|delete <ip…>] [--all] [-y]
netscan alerts [list|ack <id>|snooze <id> [hours]|reopen <id>] [--note <text>] [--all]
netscan settings export|import <file>      netscan diag [zip]
netscan update [check|apply] [--beta] [-y]  # exit 10 = update available (check)
netscan refdata [check|update]              # refresh port lists / OUI / vulnerability rules (exit 10 = newer data, check)
```

Progress goes to stderr (suppressed when stderr is not a terminal or with `-q`), results to stdout (safe to pipe). Exit codes: `0` ok, `1` error or declined confirmation, `2` bad arguments, `3` scan succeeded but risky ports were found, `10` `update check` found a newer version.

```bash
netscan --range 192.168.1.0/24 --ports 22,80,443 -o json --out scan.json
netscan --use-settings --scheduled --upload --notify -q      # cron / task-scheduler style run
netscan history inventory
netscan assets delete 192.168.1.99 -y
docker run --rm --net=host --cap-add=NET_RAW ghcr.io/<owner>/netscan --range 10.0.0.0/24
```

## Assets, alerts and assessment

- **Asset approval**: every host ever seen is in the inventory (History screen / `netscan assets list`). Approve the ones you know (`netscan assets approve 10.0.0.5` or `--all` for everything currently alive); the MAC seen at approval time is pinned. With *Alert on unapproved devices* enabled, any live host outside the approved list raises `UnapprovedHost`, and an approved IP answering with a different MAC raises `ApprovedMacMismatch`. The first scan can auto-approve everything it finds to form the baseline. Owner, tags and notes are kept per host.
- **Alert operations**: the same event is one alert no matter how many scans repeat it; acknowledge or snooze it (`netscan alerts ack <id>` / `snooze <id> [hours]`), define maintenance windows (`Mon-Fri 22:00-06:00; Sat,Sun`) during which nothing is sent, choose how often an open alert is re-sent, and alerts resolve themselves when the condition disappears.
- **Identification**: besides reverse DNS, live hosts are asked over SNMP v2c (sysDescr/sysName/sysObjectID, community configurable), mDNS and NetBIOS; the best name wins and OS/device hints replace the TTL guess.
- **Deep discovery** (Settings → Discovery, on by default; `--no-discovery` on the CLI): each live host is fingerprinted over SMB2 (NTLM: computer/domain name, exact Windows version/build), SSH (software + distribution, e.g. *Ubuntu 25.10*) and HTTP/HTTPS (server header, title, vendor web UIs, TLS certificate names); the whole network is browsed once per scan over SSDP and mDNS (friendly names, model numbers, Apple model identifiers, Chromecast/printer/TV details); UDP probes (DNS, NTP, SIP, TFTP, SSDP unicast) catch devices with no TCP service; the OS neighbour tables (ARP/NDP) and, when a community is configured, the gateway's/switches' SNMP tables (ARP, bridge FDB, LLDP) contribute hosts that never answer pings, their IPv6 addresses and the **switch port** they hang off. On Linux an active ARP sweep runs too, and an optional **passive listener** (libpcap/Npcap, needs capture privileges) keeps collecting DHCP host names, vendor classes and TCP/IP stack fingerprints between scans. Every value is stored as a *fact* with its source and confidence (visible in the host details window and in the JSON report); facts from earlier scans fill gaps with lowered confidence, and timeouts adapt to the measured round-trip times.
- **Assessment**: open ports and banners are matched against the offline rule set `data/vulnrules.json` (vulnerable versions such as old OpenSSH/nginx/Apache, exposed databases/remote-admin ports, SSH-1, plain Telnet/FTP) and TLS endpoints are inspected (expired/expiring/self-signed certificates, TLS 1.0/1.1, weak RSA keys). Each host gets a 0–100 risk score; `HighRisk` alerts fire above the configured threshold. Update the rule file with your own entries — the embedded copy is used when the file is missing.
- **Scan profiles**: *quick* (ping sweep only, 128 parallel), *standard* (your settings), *thorough* (top ~80 service ports added, identification + assessment on, slower timeouts). `--profile` on the CLI.
- **Reports**: HTML, JSON and **PDF** (Korean-capable) from the GUI, `-o pdf --out file.pdf` on the CLI; scheduled scans save CSV + HTML + PDF.
- **Operations**: settings export/import (no secrets inside), diagnostic bundle (`netscan diag` or Settings) for support, history retention (days) with daily rotating backups and restore.
- **Automatic updates** (Settings → Updates): check every N hours, download in the background, install when the app closes or click *Restart now*; opt into pre-releases (beta). Portable and development builds (not installed through the Velopack installer) still check for new versions and show an *Update* button that opens the release page instead of installing. `Update.Repository` in `settings.json` (`owner/name`) points all updaters at a fork or an internal mirror. The headless binaries update themselves too: `netscan update` (or `netscan update check`), and `netscan-service` applies updates on its own when *Install automatically* is on — downloads are verified against the release's `SHA256SUMS.txt`, files are swapped in place on Linux/macOS (the service exits with code 75 so systemd/launchd restart it) and through a helper process on Windows (which restarts the service).

## Central collector (`netscan-collector`)

Several sites can report to one server: the collector (`KetworkScanner.Collector`, Docker image `ghcr.io/<owner>/netscan-collector`) accepts the scanners' HTTPS uploads (one Bearer token per site), stores CSV/HTML/PDF/JSON reports, parses the CSVs into per-scan summaries and host lists, and serves a dashboard (`/`, `/sites/{site}`, `/reports/{id}`; sign in with a token on `/login`, rate-limited) plus a JSON API (`/api/sites`, `/api/sites/{site}/scans`, `/api/sites/{site}/scans/{id}/hosts`, `/api/uploads/{id}`, Bearer token). Each site keeps its newest `ScansPerSite` scans and report files. See [`deploy/README.md`](deploy/README.md#central-collector-netscan-collector) for configuration; put a TLS-terminating reverse proxy in front of it.

## Headless scheduler (`netscan-service`)

`netscan-service` reads the same `settings.json` as the GUI and runs the configured hourly schedule or continuous monitoring without a window — saving reports, uploading, notifying and recording history. If the machine was asleep at the top of the hour the scan still runs later in that hour. Install it with the files in [`deploy/`](deploy/README.md):

- Linux: `deploy/netscan.service` (systemd; grants `CAP_NET_RAW` so ping works without root)
- macOS: `deploy/kr.smic.netscan.plist` (launchd agent)
- Windows: `deploy/install-windows-service.ps1`
- Anywhere: `netscan-service --run-once` from cron / Task Scheduler

## Runtime configuration / data files

User data lives in a per-user folder that survives updates: `%APPDATA%\KetworkScanner` on Windows, `~/Library/Application Support/KetworkScanner` on macOS, `~/.config/KetworkScanner` on Linux. (Data an older macOS build left in `~/.config/KetworkScanner` is copied over on first start.)

| File | Purpose |
|---|---|
| `settings.json` | All settings and scan ranges (schema v2). Old `setting.ini` / `iprange.ini` are migrated once and renamed `*.migrated`. |
| `secrets/` | Encrypted-file secret store (used when no OS credential store is available). Passwords/tokens are never written to `settings.json`. |
| `history.db` | SQLite scan history (schema v3, with per-host facts/OS version/model/switch port), inventory (approvals/owners/tags) and alerts |
| `backups/` | Daily `history-*.db` backups (rotated) |
| `env/` | Saved CSV results and HTML reports |
| `outbox/` | Uploads waiting to be retried |
| `logs/` | Daily log files (14 days kept) |
| `data/` | Reference data downloaded by the automatic refresh (`reservedports.ini`, `prohibitports.ini`, `vulnrules.json`, `ouiinfo*.ini`) plus `refdata.json` with their versions and the last check time. A newer bundled copy (after an app update) takes precedence. |
| `known_hosts` | Pinned SFTP host keys. (Per-IP notes typed into the IP list are stored in `history.db`; an old `annotations.ini` is imported once and renamed `*.migrated`.) |

The bundled reference files (`ouiinfo*.ini`, `reservedports.ini`, `prohibitports.ini`, `vulnrules.json`, `refdata.json`) are resolved next to the executable. **Automatic refresh** (Settings → Updates, on by default, every 24 h): the app, CLI (`netscan refdata`, and before a scan with `--use-settings`) and service compare `data/refdata.json` in the GitHub repository with the files in use and download only the ones that changed, verifying size and SHA-256 and sanity-checking the content before swapping them in. The repository itself is refreshed weekly by the *Refresh reference data* workflow (`tools/update-ports.sh` from the IANA registry, `tools/update-oui.sh` from IEEE, `tools/refdata-manifest.sh`). The Ref. Ports screen shows the data versions and has an *Update now* button; `ReferenceData.SourceUrl` in `settings.json` points at a mirror.

## Upload and notifications

Settings → *Result upload*: choose FTPS (default), implicit FTPS, SFTP, HTTPS, or plain FTP (must be explicitly allowed; shown as insecure). Optionally pin the server's SHA-256 certificate / host-key fingerprint. For SFTP without a pin, the host key is remembered on first contact and any later change is rejected. HTTPS posts a multipart form (`name`, `file`) with a Bearer token to the configured URL.

Failed uploads are copied to `outbox/` and retried with exponential backoff (1 min → 24 h, up to 30 attempts) on every later upload, scheduled scan or service cycle.

Settings → *Notifications*: webhook URL (JSON `{"text": …}`), syslog host/port (UDP, RFC 5424) and/or SMTP. Choose whether to send all changes or only security-relevant ones (MAC changes, risky ports).

## Packaging for distribution

```bash
dotnet publish KetworkScanner.Avalonia/KetworkScanner.Avalonia.csproj -c Release -r osx-arm64 --self-contained true -o publish/osx-arm64
dotnet tool install -g vpk
vpk pack --packId KetworkScanner --packVersion 2.0.0 --packDir publish/osx-arm64 --mainExe KetworkScanner.Avalonia \
  --packTitle "Ketwork Scanner" --packAuthors SMIC --runtime osx-arm64 --channel osx --outputDir release-packages/osx-arm64
```

`vpk` packages only for the OS it runs on. On Windows add `--mainExe KetworkScanner.Avalonia.exe --icon assets/app.ico`. Channels: `win`, `win-arm64`, `osx`, `osx-x64`, `linux`, `linux-arm64`.

## Microsoft Store (MSIX)

`tools/build-msix.ps1` (Windows, needs the Windows SDK for `makeappx`/`signtool`) and `tools/build-msix.sh` (macOS/Linux with the open-source [MSIX SDK](https://github.com/microsoft/msix-packaging) `makemsix`) publish the GUI with `-p:StoreBuild=true` (Velopack self-update disabled, the Store updates the app), add the logo set from `KetworkScanner.Avalonia/Package/Assets/` and the manifest template `Package/AppxManifest.xml`, and produce `KetworkScanner-<version>.0-<arch>.msix` (plus an `.msixbundle` with `-Bundle`). The release workflow builds x64 + arm64 and a bundle on every tag (job *MSIX (Store)*).

Before the first Store submission set the identity values from Partner Center → *Product identity* as repository variables (or environment variables for the scripts): `MSIX_IDENTITY_NAME` (e.g. `12345SMIC.KetworkScanner`), `MSIX_PUBLISHER` (`CN=…` GUID form) and `MSIX_PUBLISHER_DISPLAY`. Store packages are uploaded **unsigned** (Microsoft signs them). For a local sideload test, sign with a certificate whose subject equals the Publisher (`-PfxPath`, or secrets `MSIX_PFX_BASE64`/`MSIX_PFX_PASSWORD` in CI) and run `Add-AppxPackage`. The Store build keeps its user data in the package-private `%LOCALAPPDATA%\Packages\…` redirection of `%APPDATA%`, so it does not share data with the Velopack install; the passive listener needs Npcap installed separately.

## Releases

Pushing a `v*.*.*` tag runs `.github/workflows/release.yml`, which runs the tests, then builds GUI installers for six RIDs, CLI + service archives, two multi-arch Docker images (`netscan` CLI and `netscan-collector`), and attaches everything to a GitHub Release. If these repository secrets exist the binaries are signed (and notarized on macOS): `WINDOWS_CERT_PFX_BASE64`, `WINDOWS_CERT_PASSWORD`, `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `MACOS_KEYCHAIN_PASSWORD`, `MACOS_SIGN_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`. `build-and-test.yml` builds the solution and runs the Core and CLI tests on Windows, macOS and Linux for every push (collector tests and a vulnerable-package check on Linux) and builds both Docker images; the Velopack packaging job runs only on manual dispatch.

## Known limitations

- **MAC addresses** are only resolvable inside the scanner's own subnet (ARP). Hosts behind a router show no MAC.
- **ICMP permission**: on Linux/macOS a normal user may be unable to send raw ICMP. The scan then relies on the TCP liveness fallback and logs a one-time hint. Fix: `sudo setcap cap_net_raw+ep <executable>` (the systemd unit already grants it) or run as root.
- **Unsigned installer warnings** when no signing secrets are configured: macOS → right-click → Open (or `xattr -d com.apple.quarantine <file>`); Windows SmartScreen → *More info → Run anyway*. Some antivirus products quarantine unsigned Velopack installers; use the Portable zip or whitelist it.
- Scanning is IPv4 only; IPv6 addresses are only recorded when mDNS or the neighbour tables reveal them.
- The passive listener needs libpcap (Linux/macOS) or Npcap (Windows) and capture privileges; without them it reports itself unavailable and the scan continues without it. Active ARP sweeps are Linux-only.

## License

See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for bundled components. The license for KetworkScanner itself is defined by the repository owner (`LICENSE`).
