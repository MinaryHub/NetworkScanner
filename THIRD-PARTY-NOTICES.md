# Third-party notices

NetworkScanner bundles or depends on the following third-party components.

| Component | License | Use |
|---|---|---|
| [.NET 10 runtime](https://github.com/dotnet/runtime) | MIT | Runtime (self-contained builds include it) |
| [Avalonia UI](https://github.com/AvaloniaUI/Avalonia) 11.3 | MIT | Cross-platform GUI |
| [Avalonia.Controls.DataGrid](https://github.com/AvaloniaUI/Avalonia) | MIT | Result/settings grids |
| [IBM Plex Sans / Mono](https://github.com/IBM/plex) (`assets/fonts/`) | SIL OFL 1.1 | UI and data fonts |
| [Inter font](https://github.com/rsms/inter) (via Avalonia.Fonts.Inter) | SIL OFL 1.1 | Fallback font |
| [Velopack](https://github.com/velopack/velopack) | MIT | Installers and in-app updates |
| [PDFsharp](https://github.com/empira/PDFsharp) 6.2 | MIT | PDF reports |
| [Nanum Gothic](https://github.com/google/fonts/tree/main/ofl/nanumgothic) (`assets/fonts/NanumGothic*.ttf`, licence text in `NanumGothic-OFL.txt`) | SIL OFL 1.1 | Korean glyphs in PDF reports |
| [FluentFTP](https://github.com/robinrodricks/FluentFTP) | MIT | FTP / FTPS upload |
| [SSH.NET](https://github.com/sshnet/SSH.NET) | MIT | SFTP upload |
| [Microsoft.Data.Sqlite](https://github.com/dotnet/efcore) + [SQLitePCLRaw](https://github.com/ericsink/SQLitePCL.raw) | MIT / Apache-2.0 | Scan history database |
| [Microsoft.Extensions.Hosting](https://github.com/dotnet/runtime) (+ WindowsServices, Systemd) | MIT | Headless scheduler service |
| [SharpPcap](https://github.com/dotnet-pcap/sharppcap) 6.3 + [PacketDotNet](https://github.com/dotnet-pcap/packetnet) | MIT | Optional passive packet listener (requires libpcap or [Npcap](https://npcap.com/) installed by the user — Npcap has its own licence, it is not redistributed) |
| [System.Security.Cryptography.ProtectedData](https://github.com/dotnet/runtime) | MIT | Windows DPAPI secret store |
| [IEEE OUI registry](https://standards-oui.ieee.org/) (`data/ouiinfo.ini`) | IEEE public data | MAC vendor lookup |
| Toolbar icons in `assets/` | See original authors (Kyo-Tux "Delikate" icon set and others) | Toolbar images (the app icon itself is original, `assets/icon/`) |
| [xUnit](https://github.com/xunit/xunit), [coverlet](https://github.com/coverlet-coverage/coverlet) | Apache-2.0 / MIT | Tests only |

Full license texts are available from each project's repository.
