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
dotnet test NetworkScanner.Cli.Tests/NetworkScanner.Cli.Tests.csproj            # CLI parser / table renderer
dotnet test NetworkScanner.Collector.Tests/NetworkScanner.Collector.Tests.csproj # collector (in-memory server)

# A single test
dotnet test NetworkScanner.Tests/NetworkScanner.Tests.csproj --filter "FullyQualifiedName~ScanEngineIntegrationTests"
```

Tests set `UserDataPaths.OverrideRoot` and `AppSettingsStore.SecretStore` to temp locations and run **non-parallel** (`AssemblyInfo.cs`) because of that static state. Keep test-worthy logic in Core.

## Architecture

**All real logic lives in `NetworkScanner.Core` (plain `net10.0`, no UI dependency). Core contains no `OperatingSystem.Is*`, `Process.Start` or `DllImport` outside the designated adapter files/folders: `Platform/` (ARP tables), `Secrets/` (credential stores), `Network/TtlProbe.cs` (ping utility for TTL), `Discovery/Infrastructure/` (neighbor tables, raw-socket ARP), `Capture/` (pcap), `Updates/` (self-update helper) and `UserDataPaths.cs` (per-OS data folder). `Network/NetworkProbes.cs` has one `IsWindows()` check for the ping TTL option. Do not add OS checks anywhere else.** The front-ends are thin adapters.

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
  - **Facts / deep discovery** (`Discovery/HostFacts.cs`, `FactFusion.cs`, `DiscoveryDefaults.cs`) — every identity value is a `Fact(Field, Value, Source, Confidence)` collected in `HostFacts`; `FactFields` holds the field names. Two seams: `IFactProbe.ProbeAsync(ip, openPorts, timeoutMs, ct)` (per live host) and `INetworkDiscovery.DiscoverAsync(timeoutMs, ct)` (once per scan; result keyed by IPv4, `mac:…`, `lldp:…` or `v6:…`). `DiscoveryDefaults.BuildFactProbes/BuildNetworkDiscoveries(DiscoverySettings)` assemble them from `AppSettingsData.Discovery`; `ScanServices.FactProbes/NetworkDiscoveries/PassiveSnapshot` carry them (empty in `CreateOffline`). The engine runs network discovery after the ping/ARP phase (hosts found only there are marked alive with liveness `MCAST`/`TABLE`), runs the fact probes during enrichment, merges discovered + MAC-joined + history facts (`FactFusion.MergeHistory`, lowered confidence, `history:` source prefix) and projects them with `FactFusion.ApplyTo` (OS hint only from Medium+ facts; device category tokens → `DeviceCategoryLabel`). `FactFusion.AdaptiveTimeout` (p95 RTT) tunes retry/port timeouts when `ScanOptions.AdaptiveTimeouts` is on.
    - `Discovery/Fingerprint/` — `SmbProbe` (SMB2 negotiate + NTLM challenge: names, Windows build), `SshProbe`/`SshBannerParser`, `HttpProbe`/`HttpFingerprints` (server/title/vendor UIs, TLS cert names); codecs `Smb2Codec`, `NtlmCodec`, `SpnegoCodec`.
    - `Discovery/Multicast/` — `SsdpDiscovery` (M-SEARCH + device description XML), `MdnsBrowser` (service enumeration, SRV/TXT, `AppleModels`), `UdpServiceProbes` (DNS/NTP/SSDP-unicast/TFTP/SIP), `MulticastSocketSet`.
    - `Discovery/Infrastructure/` — `NeighborTableReader`/`NeighborDiscovery` (OS ARP + NDP tables), `SnmpWalker`/`SnmpBer` + `SnmpInfrastructureDiscovery` (ipNetToMedia, dot1dTpFdb, LLDP → `switchPort`), `ActiveArpProber`/`ActiveArpDiscovery` (Linux raw sockets only; `IsSupported`).
    - `Capture/` — `PassiveListener` (SharpPcap; `Probe()` reports availability, never throws), `ObservationAggregator.SnapshotByIp()` feeds `ScanServices.PassiveSnapshot`; `DhcpCodec`, `TcpFingerprints`. Hosts start it only when `Discovery.PassiveListener` is on.
  - `Vulnerability/` — offline `RuleEngine` over `data/vulnrules.json` (embedded fallback `VulnRulesDefault`), `TlsInspector`; result = `IPInfo.RiskScore` (0-100) + `FindingsJson`. `StatusKey` is "warn" at RiskScore >= 40.
  - `Reports/PdfReport` — PDFsharp + embedded Nanum Gothic (Korean). Scheduled scans also write a PDF.
  - `Updates/ReferenceData.cs` — `ReferenceDataUpdater`: compares the repository's `data/refdata.json` (name/version/sha256/size per file, regenerated by `tools/refdata-manifest.sh`; `.github/workflows/update-refdata.yml` refreshes IANA ports + IEEE OUI weekly) with the files in use, downloads changed files into `<userdata>/data/` after SHA-256 + `Validate` checks, and records `LastCheck` in the local manifest. `DataPaths.Resolve` prefers that copy unless the bundled manifest carries a newer version. Hosts reload via `RefPortListView.LoadInfo`, `OUIInfo.LoadInfo` (clears tables) and `RuleEngine.Reload()`. Settings: `AppSettingsData.ReferenceData` (AutoUpdate, CheckIntervalHours, SourceUrl); CLI `netscan refdata [check|update]`.
  - `ScanProfiles` (quick/standard/thorough) adjust `ScanOptions` only; `AppSettingsStore.Export/Import`; `Support/DiagnosticBundle`; `History/HistoryMaintenance` (retention prune + daily `VACUUM INTO` backups, `backups/`).
  - `CsvCodec` — RFC 4180 + formula-injection guard. CSV columns are header-mapped, so old 9-column files still load.
  - `AppLogger` — daily rolling files in `<userdata>/logs`, `Sink` event for hosts to mirror to console/UI. No Windows EventLog.
  - `Localization` — all user-visible Core strings go through `Localization.T(key)` (en/ko). Do not add hardcoded Korean/English strings to Core.
- **`NetworkScanner.Avalonia`** — the only GUI. `MainWindow` implements `IScanConfigProvider` by delegating to `SettingsView`. Views: IP list, Settings (upload/notifications/limits with `AppSettingsData.Validate()`), Ref. ports, History, User guide. `UpdateService` = Velopack + GitHub Releases.
- **`NetworkScanner.Cli`** — `netscan`: scan (`--use-settings`, `--upload`, `--notify`, `--scheduled`, `--profile`, `-o csv` uses `ScanEngine.BuildCsv`, `-o pdf`) plus `history`, `assets` (incl. `delete`), `alerts`, `settings export|import`, `diag` and `update` subcommands. `CliOptions.Parse` validates ranges (IPv4 only, start <= end) and subcommand names; `CliScanOptions.Build` applies settings → `--profile` → explicit options. `--upload` without `--scheduled` writes the CSV to `env/` and sends it through `UploadService` itself. Progress → stderr (suppressed when not a terminal), results → stdout, exit codes 0/1/2/3/10. Tests: `NetworkScanner.Cli.Tests` (parser, `TableRenderer`; `InternalsVisibleTo`).
- **`NetworkScanner.Service`** — `netscan-service`: `Microsoft.Extensions.Hosting` worker (Windows Service / systemd / launchd / foreground) running the schedule from `settings.json` with last-run catch-up. Unit/plist/PowerShell installers live in `deploy/`.
- **`NetworkScanner.Collector`** — `netscan-collector`: ASP.NET Core minimal API that receives the scanners' HTTPS uploads (`POST /api/scan`, `/api/upload`, `/`; one Bearer token per site, optional admin token), stores files under `<DataDir>/sites/<site>/<yyyy>/<MM>/`, indexes them in `collector.db` (`uploads`, `scans`, `scan_hosts` incl. OS/model/service/switch port/approval; schema via `PRAGMA user_version` + add-column migration), parses CSVs with `ScanCsvParser` (header-mapped; system name taken from the engine's file naming), prunes each site to `ScansPerSite` scans + report files, and serves a JSON API (`/api/sites`, `/api/sites/{site}/scans[/{id}/hosts]`, `/api/uploads/{id}`) plus a cookie-session dashboard (`/login` form only — no `?token=`, per-IP login rate limit; `/`, `/sites/{site}`, `/reports/{id}`). Tests: `NetworkScanner.Collector.Tests` (WebApplicationFactory, temp data dir).
- **`NetworkScanner.Tests`** — xUnit, references Core only. **`NetworkScanner.Cli.Tests`** — xUnit for the CLI parser/renderer.
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
- `UserDataPaths` → `%APPDATA%\NetworkScanner` (Windows), `~/Library/Application Support/NetworkScanner` (macOS, .NET 10 mapping; old `~/.config/NetworkScanner` is migrated), `~/.config/NetworkScanner` (Linux); contents: settings.json, history.db (schema v3: facts, os_version, model, switch_port), env/, outbox/, logs/, secrets/, backups/, known_hosts (settings.json, history.db, env/, outbox/, logs/, secrets/, known_hosts). Tests override `UserDataPaths.OverrideRoot`.
- A UI-facing change usually needs a matching CLI option; put the logic in Core so it is tested once.

## Releases

Pushing `vMAJOR.MINOR.PATCH` runs `.github/workflows/release.yml`: Velopack GUI packages for win-x64/arm64, osx-arm64/x64, linux-x64/arm64 (channels `win`, `win-arm64`, `osx`, `osx-x64`, `linux`, `linux-arm64` — `UpdateService` must pick the matching channel), CLI+service archives, a `ghcr.io/<owner>/netscan` Docker image, and a GitHub Release. Code signing/notarization runs only when the documented secrets exist; otherwise packages are unsigned (Gatekeeper/SmartScreen warnings expected). `release.yml` runs a `test` job first; packaging, Docker and the release depend on it. `build-and-test.yml` builds the solution and runs the Core + CLI tests on all three OSes (collector tests and a vulnerable-package check on Linux) and builds both Docker images; Velopack packaging there is `workflow_dispatch` only.
