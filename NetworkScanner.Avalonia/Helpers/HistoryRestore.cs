using System;
using System.IO;
using NetworkScanner.History;

namespace NetworkScanner.Avalonia.Helpers
{
    // 이력 DB 복원은 엔진이 DB를 열기 전에만 안전하므로 "다음 시작 시 적용" 방식으로 한다.
    // 설정 화면의 복원 버튼이 마커 파일에 백업 경로를 적어 두고, MainWindow가 ScanServices를 만들기 전에 ApplyPending을 호출한다.
    internal static class HistoryRestore
    {
        private const string MarkerFileName = "history.restore";

        public static string MarkerPath => UserDataPaths.Resolve(MarkerFileName);

        public static void Schedule(string backupPath) => File.WriteAllText(MarkerPath, backupPath);

        // 마커가 있으면 백업을 history.db 자리에 복사하고(WAL/SHM 잔재 제거) 마커를 지운다. 복사한 원본 경로를 돌려주고, 없으면 null.
        public static string? ApplyPending()
        {
            string marker = MarkerPath;
            if (!File.Exists(marker)) return null;

            string source;
            try { source = File.ReadAllText(marker).Trim(); }
            finally { try { File.Delete(marker); } catch { } }

            if (string.IsNullOrEmpty(source) || !File.Exists(source))
                throw new FileNotFoundException(source);

            string target = ScanHistoryStore.DefaultPath;
            string? dir = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            // 이전 DB의 WAL/SHM이 남아 있으면 복원본과 섞여 손상되므로 함께 지운다.
            foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                string p = target + suffix;
                if (File.Exists(p)) File.Delete(p);
            }
            File.Copy(source, target, overwrite: true);
            return source;
        }
    }
}
