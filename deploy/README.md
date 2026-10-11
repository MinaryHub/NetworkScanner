# Deployment files

| File | Purpose |
|---|---|
| `netscan.service` | systemd unit for the headless scheduler (`netscan-service`) on Linux |
| `kr.smic.netscan.plist` | launchd agent for macOS |
| `install-windows-service.ps1` | registers `netscan-service.exe` as a Windows service |
| `Dockerfile` | container image for the `netscan` CLI (run with `--net=host --cap-add=NET_RAW`) |

The scheduler reads the same `settings.json` as the GUI (per-user data folder: `%APPDATA%\NetworkScanner`, `~/Library/Application Support/NetworkScanner` on macOS, `~/.config/NetworkScanner` on Linux).
Run `netscan-service --run-once` to execute a single scheduled-style scan (CSV + HTML report, upload, notifications) — handy for cron.
