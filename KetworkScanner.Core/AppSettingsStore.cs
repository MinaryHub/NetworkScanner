using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using KetworkScanner.Secrets;
using KetworkScanner.Upload;

namespace KetworkScanner
{
    // settings.json의 실제 읽기/쓰기를 담당한다. GUI/CLI/서비스가 공유하며, UI는 AppSettingsData를 화면 컨트롤과 매핑하는
    // 역할만 한다. 비밀번호/토큰은 JSON에 쓰지 않고 ISecretStore(OS 자격 증명 저장소 또는 암호화 파일)에 보관한다.
    // 이전 버전의 setting.ini / iprange.ini 가 있으면 최초 1회 자동 변환한다.
    public static class AppSettingsStore
    {
        public const string SettingsFileName = "settings.json";
        public const string SettingFileName = "setting.ini";    // 레거시
        public const string IPRangeFileName = "iprange.ini";    // 레거시
        public const int CurrentSchemaVersion = 2;

        public const string UploadPasswordKey = "upload-password";
        public const string UploadTokenKey = "upload-token";
        public const string SmtpPasswordKey = "smtp-password";

        public static Action<string>? OnError { get; set; }

        private static ISecretStore? _secretStore;
        private static readonly object Lock = new();

        // 테스트는 임시 디렉터리 기반 저장소를 끼운다.
        public static ISecretStore SecretStore
        {
            get => _secretStore ??= SecretStoreFactory.CreateDefault(UserDataPaths.Root);
            set => _secretStore = value;
        }

        // settings.json 전체 문서. 설정값 + 스캔 대역을 한 파일에 둔다.
        public sealed class SettingsDocument
        {
            public int SchemaVersion { get; set; } = CurrentSchemaVersion;
            public AppSettingsData Settings { get; set; } = new();
            public List<ScanRangeInfo> ScanRanges { get; set; } = new();
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };

        public static string SettingsPath => UserDataPaths.Resolve(SettingsFileName);

        public static AppSettingsData LoadSettings() => LoadDocument().Settings;

        public static SettingsDocument LoadDocument()
        {
            lock (Lock)
            {
                SettingsDocument doc = ReadDocument() ?? MigrateLegacy() ?? new SettingsDocument();
                LoadSecrets(doc.Settings);
                return doc;
            }
        }

        private static SettingsDocument? ReadDocument()
        {
            string path = SettingsPath;
            if (!File.Exists(path)) return null;
            try
            {
                var doc = JsonSerializer.Deserialize<SettingsDocument>(File.ReadAllText(path, Encoding.UTF8), JsonOptions);
                if (doc == null) return null;
                doc.Settings ??= new AppSettingsData();
                doc.ScanRanges ??= new List<ScanRangeInfo>();
                if (doc.Settings.HourEnabled == null || doc.Settings.HourEnabled.Length != 24)
                    doc.Settings.HourEnabled = NormalizeHours(doc.Settings.HourEnabled);
                return doc;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), SettingsFileName, ex.Message));
                // 깨진 파일은 덮어쓰지 않도록 백업해 둔다.
                try { File.Copy(path, path + ".corrupt", overwrite: true); } catch { }
                return null;
            }
        }

        private static bool[] NormalizeHours(bool[]? hours)
        {
            var result = new bool[24];
            if (hours != null) Array.Copy(hours, result, Math.Min(24, hours.Length));
            return result;
        }

        private static void LoadSecrets(AppSettingsData data)
        {
            try
            {
                data.Upload.Password = SecretStore.Get(UploadPasswordKey) ?? "";
                data.Upload.BearerToken = SecretStore.Get(UploadTokenKey) ?? "";
                data.Notifications.SmtpPassword = SecretStore.Get(SmtpPasswordKey) ?? "";
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), "secrets", ex.Message));
            }
        }

        private static void SaveSecrets(AppSettingsData data)
        {
            SaveSecret(UploadPasswordKey, data.Upload.Password);
            SaveSecret(UploadTokenKey, data.Upload.BearerToken);
            SaveSecret(SmtpPasswordKey, data.Notifications.SmtpPassword);
        }

        private static void SaveSecret(string key, string? value)
        {
            try
            {
                if (string.IsNullOrEmpty(value)) SecretStore.Remove(key);
                else if (!SecretStore.TrySet(key, value))
                    OnError?.Invoke(string.Format(Localization.T("msg.store.savefailed"), "secret:" + key, SecretStore.Name));
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.savefailed"), "secret:" + key, ex.Message));
            }
        }

        public static void SaveSettings(AppSettingsData data)
        {
            lock (Lock)
            {
                SettingsDocument doc = ReadDocument() ?? new SettingsDocument();
                doc.Settings = data;
                WriteDocument(doc);
                SaveSecrets(data);
            }
        }

        private static void WriteDocument(SettingsDocument doc)
        {
            try
            {
                doc.SchemaVersion = CurrentSchemaVersion;
                string path = SettingsPath;
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                string tmp = path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(doc, JsonOptions), new UTF8Encoding(false));
                File.Move(tmp, path, overwrite: true);
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.store.savefailed"), SettingsFileName, ex.Message));
            }
        }

        // 컬럼 너비만 갱신해 저장한다. 디스크의 기존 설정을 읽어 이 두 필드만 바꾸므로,
        // 사용자가 설정 화면에서 저장하지 않은 편집 내용을 덮어쓰지 않는다(창 종료 시 호출).
        public static void SaveColumnLayout(string ipListWidths, string ipRangeWidths)
        {
            lock (Lock)
            {
                SettingsDocument doc = ReadDocument() ?? new SettingsDocument();
                doc.Settings.IpListColumnWidths = ipListWidths;
                doc.Settings.IpRangeColumnWidths = ipRangeWidths;
                WriteDocument(doc);
            }
        }

        public static ScanRangeList LoadScanRanges()
        {
            var ranges = new ScanRangeList();
            SettingsDocument doc;
            lock (Lock) doc = ReadDocument() ?? MigrateLegacy() ?? new SettingsDocument();

            foreach (ScanRangeInfo r in doc.ScanRanges)
            {
                if (r == null || string.IsNullOrWhiteSpace(r.StartIP) || string.IsNullOrWhiteSpace(r.EndIP)) continue;
                ranges.AddItem(r);
            }

            // 설정된 대역이 하나도 없으면(최초 실행이거나 전부 지워진 경우) 이 PC가 속한 로컬 서브넷을 기본값으로 채워
            // 스캔 화면을 처음 열어도 바로 사용할 수 있게 한다.
            if (ranges.Count == 0)
            {
                ScanRangeInfo? localRange = LocalNetworkInfo.GetLocalSubnetRange();
                if (localRange != null) ranges.AddItem(localRange);
                SaveScanRanges(ranges);
            }

            return ranges;
        }

        public static void SaveScanRanges(ScanRangeList ranges)
        {
            lock (Lock)
            {
                SettingsDocument doc = ReadDocument() ?? new SettingsDocument();
                doc.ScanRanges = new List<ScanRangeInfo>(ranges);
                WriteDocument(doc);
            }
        }

        // ---------------------------------------------------------------- 내보내기 / 가져오기

        // 설정+대역을 JSON 파일로 내보낸다. 비밀(비밀번호/토큰)은 포함되지 않는다.
        public static void Export(string path)
        {
            SettingsDocument doc;
            lock (Lock) doc = ReadDocument() ?? new SettingsDocument();
            File.WriteAllText(path, JsonSerializer.Serialize(doc, JsonOptions), new UTF8Encoding(false));
        }

        // 내보낸 JSON을 읽어 현재 설정을 덮어쓴다(컬럼 너비·고지 확인은 현재 값 유지). 비밀은 건드리지 않는다.
        public static SettingsDocument Import(string path)
        {
            var incoming = JsonSerializer.Deserialize<SettingsDocument>(File.ReadAllText(path, Encoding.UTF8), JsonOptions)
                           ?? throw new InvalidDataException("not a settings file");
            incoming.Settings ??= new AppSettingsData();
            incoming.ScanRanges ??= new List<ScanRangeInfo>();
            lock (Lock)
            {
                SettingsDocument current = ReadDocument() ?? new SettingsDocument();
                incoming.Settings.IpListColumnWidths = current.Settings.IpListColumnWidths;
                incoming.Settings.IpRangeColumnWidths = current.Settings.IpRangeColumnWidths;
                incoming.Settings.UsageNoticeAccepted = current.Settings.UsageNoticeAccepted;
                incoming.Settings.HourEnabled = NormalizeHours(incoming.Settings.HourEnabled);
                WriteDocument(incoming);
                LoadSecrets(incoming.Settings);
            }
            return incoming;
        }

        // ---------------------------------------------------------------- 레거시 ini 변환

        private static SettingsDocument? MigrateLegacy()
        {
            string iniPath = UserDataPaths.Resolve(SettingFileName);
            string rangePath = UserDataPaths.Resolve(IPRangeFileName);
            if (!File.Exists(iniPath) && !File.Exists(rangePath)) return null;

            var doc = new SettingsDocument();
            if (File.Exists(iniPath))
            {
                try
                {
                    string? storedPassword = null;
                    foreach (string rawLine in File.ReadAllLines(iniPath))
                    {
                        if (string.IsNullOrWhiteSpace(rawLine)) continue;
                        string[] token = rawLine.Split('=', 2);
                        if (token.Length < 2) continue;
                        ApplyLegacyKey(doc.Settings, token[0].Trim(), token[1].Trim(), ref storedPassword);
                    }
                    MigrateLegacyPassword(doc.Settings, storedPassword);
                }
                catch (Exception ex)
                {
                    OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), SettingFileName, ex.Message));
                }
            }

            if (File.Exists(rangePath))
            {
                try
                {
                    foreach (string line in File.ReadAllLines(rangePath))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        string[] token = line.Split(',', 4);
                        if (token.Length < 3) continue;
                        doc.ScanRanges.Add(new ScanRangeInfo
                        {
                            Index = int.TryParse(token[0], out int idx) ? idx : 0,
                            StartIP = token[1],
                            EndIP = token[2],
                            Description = token.Length > 3 ? token[3] : "",
                        });
                    }
                }
                catch (Exception ex)
                {
                    OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), IPRangeFileName, ex.Message));
                }
            }

            WriteDocument(doc);
            SaveSecrets(doc.Settings);
            // 변환이 끝난 레거시 파일은 이름을 바꿔 두 번 변환되지 않게 한다(삭제하지 않아 되돌릴 수 있다).
            TryRename(iniPath);
            TryRename(rangePath);
            return doc;
        }

        private static void ApplyLegacyKey(AppSettingsData d, string key, string value, ref string? storedPassword)
        {
            if (key.Length == 4 && key.StartsWith("hr", StringComparison.Ordinal) && int.TryParse(key.AsSpan(2), out int hour) && hour is >= 1 and <= 24)
            {
                d.HourEnabled[hour - 1] = ParseBool(value);
                return;
            }

            switch (key)
            {
                case "usescheuling": case "usescheduling": d.UseScheduling = ParseBool(value); break;
                case "useftp": d.Upload.Enabled = ParseBool(value); break;
                case "ftpip": d.Upload.Host = value; break;
                case "ftpid": d.Upload.User = value; break;
                case "ftppw": storedPassword = value; break;
                case "ftpport": d.Upload.Port = int.TryParse(value, out int p) ? p : 0; break;
                case "systemname": d.SystemName = value; break;
                case "portlist": d.PortList = value; break;
                case "useportchecking": d.UsePortChecking = ParseBool(value); break;
                case "loadlastestfile": case "loadlatestfile": d.LoadLatestFileOnStartup = ParseBool(value); break;
                case "continuousmonitoring": d.ContinuousMonitoring = ParseBool(value); break;
                case "monitorintervalminutes": if (int.TryParse(value, out int mins)) d.MonitorIntervalMinutes = mins; break;
                case "language": d.Language = value; break;
                case "iplistcolwidths": d.IpListColumnWidths = value; break;
                case "iprangecolwidths": d.IpRangeColumnWidths = value; break;
            }
        }

        // 이전 버전은 평문 FTP만 지원했으므로, 동작이 끊기지 않도록 FTP+허용으로 옮기고 FTPS 전환을 권고한다.
        private static void MigrateLegacyPassword(AppSettingsData d, string? storedPassword)
        {
            d.Upload.Protocol = UploadProtocol.Ftp;
            d.Upload.AllowInsecure = d.Upload.Enabled;

            if (string.IsNullOrEmpty(storedPassword)) return;
            string? plain = LegacyCredentialFormat.IsKeychainMarker(storedPassword)
                ? SecretStore.Get(LegacyCredentialFormat.LegacyKey)
                : LegacyCredentialFormat.TryDecodeLegacy(storedPassword);
            if (!string.IsNullOrEmpty(plain)) d.Upload.Password = plain;
        }

        private static bool ParseBool(string value) => bool.TryParse(value, out bool b) && b;

        private static void TryRename(string path)
        {
            try { if (File.Exists(path)) File.Move(path, path + ".migrated", overwrite: true); } catch { }
        }
    }
}
