using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace KetworkScanner.History
{
    // 이력 DB 운영: 보존 기간이 지난 스캔 정리, 하루 한 번 온라인 백업(보관 개수 제한). 스캔이 끝난 뒤 호출한다.
    public static class HistoryMaintenance
    {
        public const string BackupFolderName = "backups";
        private const string StampFileName = "history-maint.txt";

        public sealed record Result(int Pruned, string? BackupPath, int BackupsDeleted);

        public static string BackupDirectory => UserDataPaths.Resolve(BackupFolderName);

        // 하루에 한 번만 실제로 돈다(스탬프 파일). force면 즉시.
        public static Result? RunIfDue(ScanHistoryStore store, int retentionDays, int backupsToKeep, DateTimeOffset now, bool force = false)
        {
            string stamp = UserDataPaths.Resolve(StampFileName);
            if (!force)
            {
                try
                {
                    if (File.Exists(stamp)
                        && DateTimeOffset.TryParse(File.ReadAllText(stamp).Trim(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var last)
                        && (now - last).TotalHours < 24)
                        return null;
                }
                catch { }
            }

            Result result = Run(store, retentionDays, backupsToKeep, now);
            try { File.WriteAllText(stamp, now.ToString("o", CultureInfo.InvariantCulture)); } catch { }
            return result;
        }

        public static Result Run(ScanHistoryStore store, int retentionDays, int backupsToKeep, DateTimeOffset now)
        {
            int pruned = 0;
            if (retentionDays > 0)
            {
                try { pruned = store.Prune(now.AddDays(-retentionDays)); }
                catch (Exception ex) { AppLogger.LogWarn("History", "prune failed: " + ex.Message); }
            }

            string? backup = null;
            int deleted = 0;
            if (backupsToKeep > 0)
            {
                try
                {
                    Directory.CreateDirectory(BackupDirectory);
                    backup = Path.Combine(BackupDirectory, $"history-{now.LocalDateTime:yyyyMMdd-HHmmss}.db");
                    store.BackupTo(backup);
                    deleted = Rotate(BackupDirectory, backupsToKeep);
                }
                catch (Exception ex)
                {
                    AppLogger.LogWarn("History", "backup failed: " + ex.Message);
                    backup = null;
                }
            }
            return new Result(pruned, backup, deleted);
        }

        // 최신 keep개만 남기고 오래된 백업을 지운다.
        public static int Rotate(string dir, int keep)
        {
            if (!Directory.Exists(dir)) return 0;
            List<FileInfo> files = new DirectoryInfo(dir).GetFiles("history-*.db").OrderByDescending(f => f.Name).ToList();
            int deleted = 0;
            foreach (FileInfo f in files.Skip(Math.Max(0, keep)))
            {
                try { f.Delete(); deleted++; } catch { }
            }
            return deleted;
        }

        public static IReadOnlyList<string> ListBackups()
        {
            if (!Directory.Exists(BackupDirectory)) return Array.Empty<string>();
            return Directory.GetFiles(BackupDirectory, "history-*.db").OrderByDescending(f => f).ToList();
        }
    }
}
