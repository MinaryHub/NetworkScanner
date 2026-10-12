# Changelog

## Unreleased (2.1.0) — commercial feature set

### Added
- **Asset approval baseline**: inventory hosts can be approved (MAC pinned at approval time), given an owner, tags and a note. Optional policy alerts on unapproved live devices (`UnapprovedHost`) and on approved hosts whose MAC changed (`ApprovedMacMismatch`). The first scan can auto-approve everything it finds. GUI inventory actions, `netscan assets …`.
- **Alert operations**: alerts are deduplicated per event, acknowledged or snoozed, suppressed during maintenance windows (`Mon-Fri 22:00-06:00; Sat,Sun`), re-notified after a configurable interval and auto-resolved when the condition disappears. Alerts view in the GUI, `netscan alerts …`.
- **Device identification** via SNMP v2c (sysDescr/sysName/sysObjectID), mDNS and NetBIOS, merged with reverse DNS; OS/device hints improve the type/OS columns.
- **Vulnerability & weak-configuration assessment** (offline rule set `data/vulnrules.json`: vulnerable service versions, exposed/legacy services, TLS certificate and protocol checks) with a per-host risk score and `HighRisk` alerts.
- **PDF report** (A4, Korean-capable embedded font) next to HTML/JSON.
- **Scan profiles** quick / standard / thorough (`--profile`), settings export/import, diagnostic support bundle (`netscan diag`), history retention and daily rotating backups with restore.
- **Central collector** (`netscan-collector`): multi-site upload endpoint with per-site tokens, stored reports, parsed scan summaries, JSON API and a dashboard; Docker image and compose-ready configuration.
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
