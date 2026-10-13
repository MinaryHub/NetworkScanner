# Deployment files

| File | Purpose |
|---|---|
| `netscan.service` | systemd unit for the headless scheduler (`netscan-service`) on Linux |
| `kr.smic.netscan.plist` | launchd agent for macOS (logs to `~/Library/Logs/netscan/`) |
| `install-windows-service.ps1` | registers `netscan-service.exe` as a Windows service (`-Credential` / `-Account` choose the run-as account) |
| `uninstall-windows-service.ps1` | stops and removes that Windows service (binaries and settings stay) |
| `Dockerfile` | container image for the `netscan` CLI (run with `--net=host --cap-add=NET_RAW`; non-root user `netscan`) |
| `Dockerfile.collector` | container image for the central collector (`netscan-collector`, listens on 8080, data in `/data`) |
| `collector.appsettings.example.json` | example collector configuration |

Both Dockerfiles take a `VERSION` build argument (`--build-arg VERSION=2.1.0`) that becomes the assembly/informational version; `release.yml` passes the tag.

## Headless scheduler (`netscan-service`)

The scheduler reads the same `settings.json` as the GUI (per-user data folder: `%APPDATA%\KetworkScanner`, `~/Library/Application Support/KetworkScanner` on macOS, `~/.config/KetworkScanner` on Linux). It validates the file on every reload and **skips scans while it is invalid** (the problem is logged once). Run `netscan-service --run-once` to execute a single scheduled-style scan (CSV + HTML + PDF report, upload, notifications) — handy for cron; the passive listener is not started in that mode.

- **Linux (systemd)**: `netscan.service` runs as user `netscan` under `ProtectSystem=strict`. `ReadWritePaths` lists `%h/.config/KetworkScanner` (the data folder of that user) and `/opt/netscan` (so the in-place self-update can replace the binaries). For an account without a home directory use the commented `StateDirectory=netscan` + `XDG_CONFIG_HOME=%S/netscan` variant instead.
- **macOS (launchd)**: the plist wraps the binary in `/bin/sh` so `$HOME` expands; stdout/stderr go to `~/Library/Logs/netscan/netscan-service.{log,err}`.
- **Windows**: `install-windows-service.ps1 [-InstallDir …] [-Credential (Get-Credential) | -Account "NT AUTHORITY\NetworkService"]`. The script prints the resolved `settings.json` path of the chosen account (LocalSystem uses the system profile, not your own `%APPDATA%`); register it with the account that uses the GUI to share one settings file. `uninstall-windows-service.ps1` removes it.
- **CLI image**: `docker run --rm --net=host --cap-add=NET_RAW -v netscan-data:/home/netscan/.config/KetworkScanner ghcr.io/<owner>/netscan --range 192.168.1.0/24`. `iputils-ping` is installed because TTL measurement (OS guess) reads the `ping` utility's output on Linux.

## Central collector (`netscan-collector`)

`deploy/Dockerfile.collector` builds the collector image; `collector.appsettings.example.json` shows the configuration. Each **token identifies a site**; the optional `AdminToken` can read every site. Configure through `appsettings.json` or environment variables:

| Setting | Env var | Default | Meaning |
|---|---|---|---|
| `Collector:DataDir` | `COLLECTOR__DATADIR` | `./collector-data` (`/data` in the image) | uploads + `collector.db` |
| `Collector:Tokens:N:Token` / `:Site` | `COLLECTOR__TOKENS__N__TOKEN` / `__SITE` | — (required) | site tokens, at least 16 characters |
| `Collector:AdminToken` | `COLLECTOR__ADMINTOKEN` | — | read-only token for all sites |
| `Collector:MaxUploadMb` | `COLLECTOR__MAXUPLOADMB` | `50` | upload size limit |
| `Collector:ScansPerSite` | `COLLECTOR__SCANSPERSITE` | `200` | retention: newest N scans per site are kept; older scan summaries, their host rows, their upload rows **and the files on disk** are deleted, and the same limit applies per report kind (html/pdf/json) |

Uploads land under `<DataDir>/sites/<site>/<yyyy>/<MM>/` and are indexed in `<DataDir>/collector.db`; CSV results are parsed into per-scan summaries and host rows (name, MAC, vendor, ports, risk, OS/version, model, device type, service banner, switch port, IPv6, approval, owner). The system name shown per scan comes from the scanner's file name (`<system>_yyyyMMdd_HHmmss[_(SCHEDULING)].csv`, underscores in the system name are preserved). The schema is versioned (`PRAGMA user_version`); older databases are migrated in place at start-up.

Point a scanner at it: Settings → Result upload → protocol **HTTPS**, host `https://collector.example.com/api/scan` (or just the host name with remote dir `api/scan`), token = that site's token. The container listens on plain HTTP 8080 — terminate TLS in a reverse proxy (nginx/Caddy/Traefik) in front of it and forward the client IP if you want the login rate limit to be per client. The image runs as the non-root `app` user (uid 1654); a bind-mounted `/data` must be writable by it. The image has a `HEALTHCHECK` on `GET /healthz` (`curl` is installed for it).

### Endpoints

| Method / path | Auth | Purpose |
|---|---|---|
| `POST /api/scan`, `POST /api/upload`, `POST /` | Bearer site token | multipart upload (`name`, `file`): `.csv`, `.html`, `.pdf`, `.json` (the three paths are aliases so any "remote dir" setting works) |
| `GET /api/sites` | Bearer | sites visible to the token with last upload / last scan |
| `GET /api/sites/{site}/scans?limit=N` | Bearer | newest scans of a site |
| `GET /api/sites/{site}/scans/{id}/hosts` | Bearer | host rows of one scan |
| `GET /api/uploads/{id}` | Bearer | download a stored file |
| `GET /reports/{id}` | dashboard cookie (or Bearer) | the same download for browser sessions — the dashboard links point here |
| `GET /login`, `POST /login` | — | sign-in form; the token is stored in an `HttpOnly` cookie (30 days). `?token=` in the URL is **not** accepted. Failed sign-ins are rate-limited per client IP: 10 failures per 15 minutes, then HTTP 429 |
| `POST /logout` | cookie | clears the cookie |
| `GET /` | cookie | site overview |
| `GET /sites/{site}` | cookie | recent scans + hosts of the newest scan (Model / OS / Service columns included) |
| `GET /healthz` | — | liveness probe (`ok`) |
