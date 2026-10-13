using System;
using System.Collections.Generic;
using System.IO;

namespace KetworkScanner
{
    // 사용자 데이터(settings.json, history.db, env/ 스캔 결과 등)의 저장 위치.
    // 예전에는 작업 디렉터리에 저장했지만, Velopack 설치본은 업데이트 때 앱 폴더가 통째로
    // 교체되어 그 안의 데이터가 유실된다. 그래서 사용자 프로필의 고정 폴더에 저장하고,
    // 예전 위치에 파일이 남아 있으면 최초 1회 복사해 온다(기존 사용자 값 유지).
    public static class UserDataPaths
    {
        // 저장 위치를 바꿀 때 사용(테스트 등). 설정하면 마이그레이션은 수행하지 않는다.
        public static string? OverrideRoot { get; set; }

        private static string? _root;

        // Windows: %APPDATA%\KetworkScanner, macOS: ~/Library/Application Support/KetworkScanner, Linux: ~/.config/KetworkScanner
        public static string Root => OverrideRoot ?? (_root ??= ResolveRoot());

        public static string Resolve(string fileName) => Path.Combine(Root, fileName);

        private static string ResolveRoot()
        {
            string root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData,
                                          Environment.SpecialFolderOption.Create),
                "KetworkScanner");
            Directory.CreateDirectory(root);
            MigrateLegacyFiles(root);
            return root;
        }

        // 이름 변경 전 제품 폴더 이름. 기존 사용자의 설정·이력·비밀을 새 폴더로 1회 복사하는 데 쓴다.
        public const string LegacyProductFolder = "NetworkScanner";

        private static void CopyDirectoryOnce(string source, string target)
        {
            if (!Directory.Exists(source) || Directory.Exists(target)) return;
            Directory.CreateDirectory(target);
            foreach (string src in Directory.GetFiles(source))
                File.Copy(src, Path.Combine(target, Path.GetFileName(src)));
        }

        // 예전 저장 위치(작업 디렉터리, 실행 파일 폴더)에 남아 있는 데이터를 새 위치로 1회 복사한다.
        // 이미 새 위치에 같은 파일이 있으면 건드리지 않는다. 실패해도 앱 동작에는 지장 없다(최선 노력).
        private static void MigrateLegacyFiles(string root)
        {
            var candidates = new List<string> { Directory.GetCurrentDirectory(), AppContext.BaseDirectory };
            // 이름 변경 전(NetworkScanner) 폴더: 같은 OS 기본 위치의 옛 이름 폴더에서 1회 복사한다.
            candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), LegacyProductFolder));
            // macOS: .NET 8 시절 ApplicationData는 ~/.config 이었고 .NET 10부터 ~/Library/Application Support 로 바뀌었다.
            // 이전 버전이 남긴 ~/.config/NetworkScanner 도 이관 후보에 넣는다.
            if (OperatingSystem.IsMacOS())
            {
                candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", LegacyProductFolder));
            }
            string[] files =
            {
                AppSettingsStore.SettingFileName,
                AppSettingsStore.IPRangeFileName,
                History.ScanHistoryStore.LegacyAnnotationsFileName, // 새 위치의 history.db가 열릴 때 hosts.note로 이관된다
            };

            foreach (string dir in candidates)
            {
                try
                {
                    if (Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar)
                        == Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)) continue;

                    foreach (string name in files)
                    {
                        string legacy = Path.Combine(dir, name);
                        string target = Path.Combine(root, name);
                        if (File.Exists(legacy) && !File.Exists(target)) File.Copy(legacy, target);
                    }

                    // 새 형식(settings.json, history.db 등)은 이전 OS별 기본 폴더(옛 제품 이름 폴더)에서만 옮긴다(작업 디렉터리의 우연한 파일은 무시).
                    if (string.Equals(Path.GetFileName(dir.TrimEnd(Path.DirectorySeparatorChar)), LegacyProductFolder, StringComparison.Ordinal))
                    {
                        foreach (string name in new[] { AppSettingsStore.SettingsFileName, "history.db", "known_hosts", "history-maint.txt" })
                        {
                            string legacy = Path.Combine(dir, name);
                            string target = Path.Combine(root, name);
                            if (File.Exists(legacy) && !File.Exists(target)) File.Copy(legacy, target);
                        }
                        foreach (string sub in new[] { "secrets", "outbox", "backups", "data" })
                            CopyDirectoryOnce(Path.Combine(dir, sub), Path.Combine(root, sub));
                    }

                    // 스캔 결과 CSV 폴더도 함께 이관한다(시작 시 최근 기록 열기가 계속 동작하도록).
                    string legacyEnv = Path.Combine(dir, "env");
                    if (Directory.Exists(legacyEnv))
                    {
                        string targetEnv = Path.Combine(root, "env");
                        Directory.CreateDirectory(targetEnv);
                        foreach (string src in Directory.GetFiles(legacyEnv))
                        {
                            string dst = Path.Combine(targetEnv, Path.GetFileName(src));
                            if (!File.Exists(dst)) File.Copy(src, dst);
                        }
                    }
                }
                catch
                {
                    // 마이그레이션 실패는 무시 - 새 위치를 빈 상태로 쓰기 시작한다.
                }
            }
        }
    }
}
