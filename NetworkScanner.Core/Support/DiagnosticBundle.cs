using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using NetworkScanner.History;

namespace NetworkScanner.Support
{
    // 지원 요청용 진단 번들(zip): 버전/OS/경로, 설정(비밀 없음), 최근 로그, outbox 메타, 이력 요약, 크래시 파일.
    // 비밀번호·토큰은 settings.json에 애초에 없고(ISecretStore), secrets/ 폴더와 history.db 본문은 넣지 않는다.
    public static class DiagnosticBundle
    {
        public static string DefaultPath()
            => Path.Combine(UserDataPaths.Root, $"netscan-diag-{DateTime.Now:yyyyMMdd-HHmmss}.zip");

        public static string Create(string? zipPath = null, int logDays = 7, ScanHistoryStore? history = null)
        {
            string path = zipPath ?? DefaultPath();
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            if (File.Exists(path)) File.Delete(path);

            using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
            AddText(zip, "info.txt", BuildInfo(history));
            AddFileIfExists(zip, AppSettingsStore.SettingsPath, "settings.json");
            AddFileIfExists(zip, UserDataPaths.Resolve("known_hosts"), "known_hosts");
            AddFileIfExists(zip, Path.Combine(AppLogger.LogsDirectory, "crash.txt"), "crash.txt");

            string logs = AppLogger.LogsDirectory;
            if (Directory.Exists(logs))
            {
                DateTime cutoff = DateTime.Now.AddDays(-logDays);
                foreach (string f in Directory.EnumerateFiles(logs, "*.log"))
                {
                    if (File.GetLastWriteTime(f) >= cutoff) AddFileIfExists(zip, f, "logs/" + Path.GetFileName(f));
                }
            }

            string outbox = UserDataPaths.Resolve("outbox");
            if (Directory.Exists(outbox))
            {
                foreach (string f in Directory.EnumerateFiles(outbox, "*.json"))
                    AddFileIfExists(zip, f, "outbox/" + Path.GetFileName(f));
            }

            return path;
        }

        private static string BuildInfo(ScanHistoryStore? history)
        {
            var sb = new StringBuilder();
            Assembly entry = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            sb.AppendLine("NetworkScanner diagnostic bundle");
            sb.AppendLine("created: " + DateTimeOffset.Now.ToString("o", CultureInfo.InvariantCulture));
            sb.AppendLine("app: " + entry.GetName().Name + " " + entry.GetName().Version);
            sb.AppendLine("core: " + typeof(DiagnosticBundle).Assembly.GetName().Version);
            sb.AppendLine("os: " + RuntimeInformation.OSDescription + " (" + RuntimeInformation.OSArchitecture + ")");
            sb.AppendLine("runtime: " + RuntimeInformation.FrameworkDescription + " (" + RuntimeInformation.ProcessArchitecture + ")");
            sb.AppendLine("culture: " + CultureInfo.CurrentCulture.Name + " / ui " + CultureInfo.CurrentUICulture.Name + " / tz " + TimeZoneInfo.Local.Id);
            sb.AppendLine("user data: " + UserDataPaths.Root);
            sb.AppendLine("secret store: " + SafeName(() => AppSettingsStore.SecretStore.Name));
            sb.AppendLine("language: " + Localization.Current);
            sb.AppendLine();

            sb.AppendLine("[files]");
            foreach (string name in new[] { "settings.json", "history.db", "known_hosts" })
            {
                string p = UserDataPaths.Resolve(name);
                sb.AppendLine($"{name}: {(File.Exists(p) ? new FileInfo(p).Length.ToString(CultureInfo.InvariantCulture) + " bytes" : "missing")}");
            }
            sb.AppendLine("env/: " + CountFiles(UserDataPaths.Resolve("env")) + " files");
            sb.AppendLine("outbox/: " + CountFiles(UserDataPaths.Resolve("outbox")) + " files");
            sb.AppendLine();

            if (history != null)
            {
                try
                {
                    var scans = history.ListScans(5);
                    sb.AppendLine("[history]");
                    sb.AppendLine("inventory hosts: " + history.GetInventory().Count);
                    sb.AppendLine("open alerts: " + history.ListAlerts().Count);
                    sb.AppendLine("db size: " + history.FileSizeBytes + " bytes");
                    foreach (var s in scans)
                        sb.AppendLine($"scan {s.Id}: {s.StartedAt:u} total={s.Total} alive={s.Alive} risky={s.Prohibited} scheduled={s.Scheduled}");
                }
                catch (Exception ex) { sb.AppendLine("[history] unavailable: " + ex.Message); }
            }

            sb.AppendLine();
            sb.AppendLine("[network interfaces]");
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                    var addrs = new List<string>();
                    foreach (var a in nic.GetIPProperties().UnicastAddresses)
                        if (a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) addrs.Add(a.Address + "/" + a.PrefixLength);
                    sb.AppendLine($"{nic.Name} ({nic.NetworkInterfaceType}): {string.Join(", ", addrs)}");
                }
            }
            catch (Exception ex) { sb.AppendLine("unavailable: " + ex.Message); }
            return sb.ToString();
        }

        private static string SafeName(Func<string> f) { try { return f(); } catch { return "?"; } }

        private static int CountFiles(string dir)
        {
            try { return Directory.Exists(dir) ? Directory.GetFiles(dir).Length : 0; } catch { return 0; }
        }

        private static void AddText(ZipArchive zip, string name, string text)
        {
            ZipArchiveEntry e = zip.CreateEntry(name, CompressionLevel.Optimal);
            using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
            w.Write(text);
        }

        private static void AddFileIfExists(ZipArchive zip, string path, string name)
        {
            try { if (File.Exists(path)) zip.CreateEntryFromFile(path, name, CompressionLevel.Optimal); }
            catch (Exception ex) { AddText(zip, name + ".error.txt", ex.Message); }
        }
    }
}
