# Changelog

## Unreleased (2.1.0) — commercial feature set

### Changed (clean-up round)
- Settings: the "Device identification" and "Deep discovery" groups are one card (Names / Fingerprints / Network rows, one SNMP community); vulnerability assessment sits next to the port settings; the duplicate profile selector, the duplicate History backup button and the fixed 90-day prune are gone (prune uses the retention setting); hours are labelled 00–23; a hint shows when discovery changes need a restart.
- IP list: search covers model, OS, OS version, type, service and switch port; port checks sit in one "Check ports" submenu; Approve/Unapprove in the context menu; the "Type" column shows the probed category only (the model has its own column); the status legend is gone; column widths are saved by column id, so adding columns no longer scrambles them.
- Host details show model, MAC, vendor, IPv6, open ports and service, with localized severity/confidence labels. Inventory shows model, OS and note.
- Per-IP notes typed into the IP list now live in the history database (`hosts.note`) instead of `annotations.ini`, which is imported once.
- User guide rewritten for the current feature set in English and Korean (Japanese/Chinese dropped).
- Active ARP sweep now actually runs when enabled; the warning status label and icon follow one rule; profiles no longer leak settings into each other; plaintext banner grabs skip TLS ports.
- CLI: `-o csv` writes the engine's CSV (loadable by the GUI and collector), `--upload` works without `--scheduled`, `--profile` no longer overrides an explicit `--parallelism`, strict subcommand/argument validation, `assets delete`, settings validation warnings, accurate help; new `NetworkScanner.Cli.Tests`.
- Service: validated settings, minimum monitor interval, system name resolved once, passive observations pruned, `--run-once` skips the listener; systemd unit allows in-place self-update; Windows install script takes an account and an uninstall script exists.
- Collector: dashboard download links work with a browser session, retention also removes old upload rows and files, system names with underscores parse correctly, host rows keep OS/model/service/switch port/IPv6/owner, login is rate-limited and tokens are no longer accepted in the URL.
- CI: release runs tests first and waits for the Docker images; the retired `macos-13` runner was replaced; Docker images get the release version, run as non-root and include `ping`/`curl`; `.dockerignore` added.
- Removed dead code (PingTester, AnnotationStore, legacy FTP aliases, unused codec builders, unused localization keys).

### Added
- **Asset approval baseline**: inventory hosts can be approved (MAC pinned at approval time), given an owner, tags and a note. Optional policy alerts on unapproved live devices (`UnapprovedHost`) and on approved hosts whose MAC changed (`ApprovedMacMismatch`). The first scan can auto-approve everything it finds. GUI inventory actions, `netscan assets …`.
- **Alert operations**: alerts are deduplicated per event, acknowledged or snoozed, suppressed during maintenance windows (`Mon-Fri 22:00-06:00; Sat,Sun`), re-notified after a configurable interval and auto-resolved when the condition disappears. Alerts view in the GUI, `netscan alerts …`.
- **Device identification** via SNMP v2c (sysDescr/sysName/sysObjectID), mDNS and NetBIOS, merged with reverse DNS; OS/device hints improve the type/OS columns.
- **Vulnerability & weak-configuration assessment** (offline rule set `data/vulnrules.json`: vulnerable service versions, exposed/legacy services, TLS certificate and protocol checks) with a per-host risk score and `HighRisk` alerts.
- **PDF report** (A4, Korean-capable embedded font) next to HTML/JSON.
- **Scan profiles** quick / standard / thorough (`--profile`), settings export/import, diagnostic support bundle (`netscan diag`), history retention and daily rotating backups with restore.
- **Central collector** (`netscan-collector`): multi-site upload endpoint with per-site tokens, stored reports, parsed scan summaries, JSON API and a dashboard; Docker image and compose-ready configuration.
- **Deep discovery / accuracy round**: missed hosts are recovered by ping retries with adaptive timeouts, the ARP cache, SSDP/mDNS browsing and the OS/router neighbour tables (liveness `MCAST`/`TABLE`); TTL is now measured on every OS. Live hosts are fingerprinted over SMB2/NTLM (computer and domain name, exact Windows build), SSH (software, distribution/version) and HTTP(S) (server, title, vendor web UIs, certificate names); SSDP and mDNS add friendly names, model numbers and Apple/Chromecast/printer/TV details; UDP probes (DNS/NTP/SIP/TFTP/SSDP) cover hosts without TCP services; SNMP tables of the gateway or configured switches add ARP/FDB/LLDP data and the switch port per host; IPv6 neighbours are recorded; Linux gets an active ARP sweep and an optional passive libpcap listener (DHCP names/vendor classes, TCP/IP fingerprints). Every value is a *fact* with source and confidence (host details → Evidence, JSON `facts` array), facts from earlier scans fill gaps at lower confidence, and the OUI lookup understands MA-M/MA-S blocks and labels randomized MACs. New columns: Model, OS version, Switch port; new `Discovery` settings block (`--no-discovery` on the CLI); history schema v3.
- **Automatic updates**: the GUI checks on a schedule (default every 6 h), downloads in the background and can install silently when the app closes (or on demand), with an optional beta (pre-release) channel; the CLI and service update themselves from GitHub Releases (`netscan update`, service `Update.AutoApply`) after verifying the archive against `SHA256SUMS.txt`, swapping files in place on Unix and via a helper process on Windows.

## Unreleased (2.0.0)

Platform-independent, production-hardening rewrite. Everything below ships in one release.

### Breaking / migration
- **.NET 10 (LTS)** is required to build. Release packages are self-contained, so end users need nothing.
- The Windows-only WPF UI, the `OUIConvertor` WPF utility and the legacy `.vdproj` installer were removed. The Avalonia app is the only GUI.
- Settings moved from `setting.ini` / `iprange.ini` to **`settings.json`** (schema v2). Existing files are migrated automatically once and renamed to `*.migrated`.
- Passwords are no longer stored in the settings file. They go to the OS credential store (DPAPI / Keychain / libsecret) or, where none exists, to an AES-256-GCM encrypted file under the user data folder. The old Base64 fallback is gone.
- Upload defaults to **FTPS (explicit TLS)**. Migrated configurations keep working on plain FTP but are flagged as insecure; switch to FTPS/SFTP/HTTPS in Settings.
- CSV files now follow RFC 4180 (quoted fields). New columns `Service`, `Ttl`, `HasProhibitedPort`. Old files still load.
- `IScanConfigProvider.GetFTP*()` was replaced by `GetUploadSettings()`; `ScanEngine` takes a `ScanServices` bundle.

### Added
- Native ARP table readers (`/proc/net/arp`, macOS `sysctl`, Windows `GetIpNetTable2`) — no `arp` binary required.
- SQLite scan history (`history.db`): scan list, per-host history, inventory with first/last seen; used as the change-detection baseline after a restart. History view in the GUI, `netscan history` in the CLI.
- Upload outbox with exponential-backoff retries; SFTP with host-key pinning/TOFU; HTTPS collector upload with Bearer token; certificate fingerprint pinning.
- Notifications on detected changes: webhook (Slack/Teams/Discord), syslog (UDP RFC 5424), SMTP.
- Headless scheduler service `netscan-service` (Windows Service / systemd / launchd / `--run-once`) with last-run catch-up after sleep.
- CLI: `--use-settings`, `--upload`, `--notify`, `--scheduled`, `--parallelism`, `-o html`, exit code 3 on risky ports, Docker image.
- Settings validation with localized error messages; scan safety limits (parallelism, max addresses).
- Logging to daily rolling files under `<userdata>/logs` with crash capture.
- CI: tests and full build on Windows/macOS/Linux, vulnerable-package check, Docker build; release packages for win-x64/arm64, osx-arm64/x64, linux-x64/arm64; optional code signing/notarization via secrets.

### Fixed
- CSV rows with commas/quotes in names or notes no longer corrupt the file; spreadsheet formula injection is neutralised.
- Invalid FTP host/port no longer crashes the app.
- Per-host port checks run in parallel; progress messages are throttled so the UI stays responsive on large ranges.
- All Core messages are localized (en/ko); file names and dates are culture-invariant; file lookups are case-insensitive on Linux.

## 1.7.x
See the Git history for earlier releases.
