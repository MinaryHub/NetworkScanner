# Deployment files

| File | Purpose |
|---|---|
| `netscan.service` | systemd unit for the headless scheduler (`netscan-service`) on Linux |
| `kr.smic.netscan.plist` | launchd agent for macOS |
| `install-windows-service.ps1` | registers `netscan-service.exe` as a Windows service |
| `Dockerfile` | container image for the `netscan` CLI (run with `--net=host --cap-add=NET_RAW`) |

## Central collector (`netscan-collector`)

`deploy/Dockerfile.collector` builds the collector image; `collector.appsettings.example.json` shows the configuration. Each **token identifies a site**; the optional `AdminToken` can read every site. Configure through `appsettings.json` or environment variables (`COLLECTOR__TOKENS__0__TOKEN`, `COLLECTOR__TOKENS__0__SITE`, `COLLECTOR__ADMINTOKEN`, `COLLECTOR__DATADIR`, `COLLECTOR__MAXUPLOADMB`). Uploads land under `<DataDir>/sites/<site>/<yyyy>/<MM>/` and are indexed in `<DataDir>/collector.db`; CSV results are parsed into per-scan summaries and host rows.

Point a scanner at it: Settings → Result upload → protocol **HTTPS**, host `https://collector.example.com/api/scan` (or just the host name with remote dir `api/scan`), token = that site's token. The container listens on plain HTTP 8080 — terminate TLS in a reverse proxy (nginx/Caddy/Traefik) in front of it. Dashboard: `https://collector.example.com/` (log in with a token); JSON API: `GET /api/sites`, `/api/sites/{site}/scans`, `/api/sites/{site}/scans/{id}/hosts`, `/api/uploads/{id}`; `GET /healthz` for probes.

The scheduler reads the same `settings.json` as the GUI (per-user data folder: `%APPDATA%\NetworkScanner`, `~/Library/Application Support/NetworkScanner` on macOS, `~/.config/NetworkScanner` on Linux).
Run `netscan-service --run-once` to execute a single scheduled-style scan (CSV + HTML report, upload, notifications) — handy for cron.
