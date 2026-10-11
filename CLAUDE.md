# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A network inventory / security scanner: pings an IP range, records each host's alive state, open TCP ports, MAC/vendor, hostname and service banner, flags open ports that match a reserved/prohibited (backdoor) port list, detects changes between scans, keeps a SQLite history, saves CSV/HTML/JSON reports, uploads them (FTPS/SFTP/HTTPS) with a retry outbox, and sends alerts (webhook/syslog/SMTP). One engine (`NetworkScanner.Core`) is driven by three front-ends: a cross-platform Avalonia GUI, a CLI (`netscan`) and a headless scheduler service (`netscan-service`).

## Build / test / run

Requires the **.NET 10 SDK** (all projects target `net10.0`). On this machine it is installed under `~/.dotnet`; if `dotnet --version` shows 9.x, prefix commands with `PATH="$HOME/.dotnet:$PATH" DOTNET_ROOT="$HOME/.dotnet"`.

```bash
# Whole solution — builds on Windows, macOS and Linux (there are no OS-specific projects)
dotnet build NetworkScanner.sln

# GUI
dotnet run --project NetworkScanner.Avalonia

# CLI
dotnet run --project NetworkScanner.Cli -- --range 192.168.1.0/24 --ports 22,80
dotnet run --project NetworkScanner.Cli -- history inventory

# Headless scheduler (foreground; --run-once for a single scheduled-style scan)
dotnet run --project NetworkScanner.Service -- --run-once

# Tests (xUnit, Core only, no network needed except two loopback tests)
dotnet test NetworkScanner.Tests/NetworkScanner.Tests.csproj

# A single test
dotnet test NetworkScanner.Tests/NetworkScanner.Tests.csproj --filter "FullyQualifiedName~ScanEngineIntegrationTests"
```

Tests set `UserDataPaths.OverrideRoot` and `AppSettingsStore.SecretStore` to temp locations and run **non-parallel** (`AssemblyInfo.cs`) because of that static state. Keep test-worthy logic in Core.

## Architecture

**All real logic lives in `NetworkScanner.Core` (plain `net10.0`, no UI dependency). Core contains no `OperatingSystem.Is*`, `Process.Start` or `DllImport` outside the designated adapter folders (`Platform/`, `Secrets/`).** The front-ends are thin adapters.

- **`NetworkScanner.Core`**
  - `ScanEngine` — the center. Two-phase range scan (parallel ping + TCP liveness → enrichment of alive hosts), single-host port checks, CSV load/save, change detection, history recording, report + upload.
  - `ScanServices` — the dependency bundle the engine uses: `IPinger`, `IPortProber`, `IHostNameResolver` (`Network/NetworkProbes.cs`), `IArpResolver` (`Platform/`), `UploadService` (`Upload/`), `ScanHistoryStore` (`History/`), `Clock`. `ScanServices.CreateDefault()` for apps, `CreateOffline(...)` + fakes for tests.
  - `ScanOptions` — timeouts, parallelism, `MaxTargets` safety cap. `ScanOptions.FromSettings(AppSettingsData)`.
  - `IScanConfigProvider` — the seam front-ends implement (port list, `UploadSettings`, system name, port lists, ranges). The engine never reads UI controls.
  - `AppSettingsStore` — `settings.json` (schema v2) in the user data folder; migrates legacy `setting.ini`/`iprange.ini` once (renamed to `*.migrated`). Secrets never go to JSON: they live in `ISecretStore` under keys `upload-password`, `upload-token`, `smtp-password`.
  - `Secrets/` — `ISecretStore`: DPAPI (Windows), Keychain via `security -i` on stdin (macOS), `secret-tool` (Linux), with `EncryptedFileSecretStore` (AES-256-GCM, key file 0600) as the always-available fallback. **No Base64 fallback exists any more.** `LegacyCredentialFormat` decodes old ini values during migration.
  - `Platform/` — native ARP table readers: `/proc/net/arp` (Linux), `sysctl` routing socket (macOS, header 92 bytes — verified), `GetIpNetTable2` (Windows). No `arp` binary needed (macOS falls back to `arp -an` only if sysctl fails).
  - `Upload/` — `IResultUploader` implementations `FtpUploader` (FTP/FTPS explicit/implicit, cert fingerprint pin), `SftpUploader` (SSH.NET, host-key pin or TOFU `known_hosts`), `HttpsUploader` (multipart + Bearer). `UploadOutbox` queues failures with backoff; `UploadService` = try now, else enqueue, then flush.
  - `History/` — `ScanHistoryStore` (SQLite `history.db`, WAL): scans, per-scan hosts, inventory (first/last seen). Also the change-detection baseline after a restart.
  - `Notifications/` — `Notifier` with webhook / syslog(UDP RFC 5424) / SMTP channels. It is fed by `AlertsProcessed`, not by raw changes.
  - `Alerts/` — `AlertManager`: dedupes changes into `alerts` rows (SQLite), honours ack/snooze, maintenance windows (`MaintenanceWindow.ParseList`), re-notify interval, auto-resolves state-type alerts. `AlertOutcome.ChangesToNotify` is what hosts send.
  - Asset approval lives in the `hosts` table (`approved`, `approved_mac`, `owner`, `tags`, `note`); `ScanDiff.ComputeChanges(baseline, current, approved, AssetPolicy)` emits `UnapprovedHost` / `ApprovedMacMismatch` / `HighRisk`.
  - `Discovery/` — `IIdentityProbe`: SNMP v2c, mDNS (unicast PTR), NetBIOS NBSTAT, hand-written codecs; `CompositeIdentityProbe` + `HostIdentityMerge.ChooseName`. The engine builds the composite from `ScanOptions` (`SnmpEnabled`, `MdnsEnabled`, `NetBiosEnabled`, `SnmpCommunity`) unless `ScanServices.Identity` is set or `IdentityDisabled`.
  - `Vulnerability/` — offline `RuleEngine` over `data/vulnrules.json` (embedded fallback `VulnRulesDefault`), `TlsInspector`; result = `IPInfo.RiskScore` (0-100) + `FindingsJson`. `StatusKey` is "warn" at RiskScore >= 40.
  - `Reports/PdfReport` — PDFsharp + embedded Nanum Gothic (Korean). Scheduled scans also write a PDF.
  - `ScanProfiles` (quick/standard/thorough) adjust `ScanOptions` only; `AppSettingsStore.Export/Import`; `Support/DiagnosticBundle`; `History/HistoryMaintenance` (retention prune + daily `VACUUM INTO` backups, `backups/`).
  - `CsvCodec` — RFC 4180 + formula-injection guard. CSV columns are header-mapped, so old 9-column files still load.
  - `AppLogger` — daily rolling files in `<userdata>/logs`, `Sink` event for hosts to mirror to console/UI. No Windows EventLog.
  - `Localization` — all user-visible Core strings go through `Localization.T(key)` (en/ko). Do not add hardcoded Korean/English strings to Core.
- **`NetworkScanner.Avalonia`** — the only GUI. `MainWindow` implements `IScanConfigProvider` by delegating to `SettingsView`. Views: IP list, Settings (upload/notifications/limits with `AppSettingsData.Validate()`), Ref. ports, History, User guide. `UpdateService` = Velopack + GitHub Releases.
- **`NetworkScanner.Cli`** — `netscan`: scan (`--use-settings`, `--upload`, `--notify`, `--scheduled`, `--profile`, `-o pdf`) plus `history`, `assets`, `alerts`, `settings export|import` and `diag` subcommands. Progress → stderr, results → stdout, exit code 3 when risky ports were found.
- **`NetworkScanner.Service`** — `netscan-service`: `Microsoft.Extensions.Hosting` worker (Windows Service / systemd / launchd / foreground) running the schedule from `settings.json` with last-run catch-up. Unit/plist/PowerShell installers live in `deploy/`.
- **`NetworkScanner.Tests`** — xUnit, references Core only.
- **`data/`** — `ouiinfo.ini` (raw IEEE `oui.txt`; refresh with `tools/update-oui.sh`), `reservedports.ini`, `prohibitports.ini`; linked into the GUI/CLI/service outputs. **`assets/`** — icon and toolbar images.

### Events and threading (read before touching the scan loop)

The engine reports through events; UI handlers marshal to the UI thread: `Message`, `ProgressMaxChanged`, `ProgressChanged`, `ResultsSummaryChanged`, `ItemsRefreshNeeded`, `ScanStarted`, `ScanFinished`, `ScanChangesDetected`. Progress messages are throttled (~150 ms) by `MessageThrottle`.

`DoScanAllRange` runs IPs through `Parallel.ForEachAsync` (`ScanOptions.Parallelism`, default 64); per-host ports are probed concurrently (`PortParallelism`). Results arrive on many threads:
- `_items` writes are serialized under `ScanEngine.ItemsSyncRoot`; `ItemsRefreshNeeded` is fired **outside** that lock.
- Config is read once before the loop, never per IP.
- Avalonia rebuilds its grid from a snapshot copied under the lock and coalesces refreshes. `IPInfo` does **not** implement `INotifyPropertyChanged`.
- `Start*` methods are guarded by `TryBeginScan` (one scan at a time) and wrapped in `RunTracked`.

### Cross-platform rules

- IPv4 math uses `uint32` (`IPRangeUtil`); never last-octet math.
- Use `CultureInfo.InvariantCulture` for anything persisted; UTF-8 without BOM for files; case-insensitive file matching (`EnumerationOptions`).
- `UserDataPaths` → `%APPDATA%\NetworkScanner` (Windows), `~/Library/Application Support/NetworkScanner` (macOS, .NET 10 mapping; old `~/.config/NetworkScanner` is migrated), `~/.config/NetworkScanner` (Linux); contents: settings.json, history.db (schema v2), env/, outbox/, logs/, secrets/, backups/, known_hosts (settings.json, history.db, env/, outbox/, logs/, secrets/, known_hosts). Tests override `UserDataPaths.OverrideRoot`.
- A UI-facing change usually needs a matching CLI option; put the logic in Core so it is tested once.

## Releases

Pushing `vMAJOR.MINOR.PATCH` runs `.github/workflows/release.yml`: Velopack GUI packages for win-x64/arm64, osx-arm64/x64, linux-x64/arm64 (channels `win`, `win-arm64`, `osx`, `osx-x64`, `linux`, `linux-arm64` — `UpdateService` must pick the matching channel), CLI+service archives, a `ghcr.io/<owner>/netscan` Docker image, and a GitHub Release. Code signing/notarization runs only when the documented secrets exist; otherwise packages are unsigned (Gatekeeper/SmartScreen warnings expected). `build-and-test.yml` runs tests and the full build on all three OSes plus a vulnerable-package check.
