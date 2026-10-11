# Changelog

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
