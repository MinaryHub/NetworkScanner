using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace KetworkScanner
{
    public enum LogLevel { Debug, Info, Warn, Error }

    // 크로스플랫폼 파일 로거. 사용자 데이터 폴더의 logs/ 아래에 날짜별 파일로 기록하고 오래된 파일은 지운다.
    // 앱 폴더(Velopack 업데이트 시 교체됨)나 OS 이벤트 로그(관리자 권한 필요)에는 의존하지 않는다.
    // 호스트(GUI/CLI/서비스)는 Sink를 추가해 콘솔 등으로도 흘려보낼 수 있다.
    public static class AppLogger
    {
        public const string LogsFolderName = "logs";
        public static int RetainDays { get; set; } = 14;
        public static LogLevel MinimumLevel { get; set; } = LogLevel.Info;

        // 파일 외에 추가로 받을 곳(예: 콘솔, UI 로그 창). 어떤 스레드에서든 호출될 수 있다.
        public static event Action<LogLevel, string, string>? Sink;

        private static readonly object _lock = new();
        private static string? _currentFile;
        private static DateTime _currentDate;

        public static string LogsDirectory => UserDataPaths.Resolve(LogsFolderName);

        public static void LogError(string source, string message) => Log(LogLevel.Error, source, message);
        public static void LogWarn(string source, string message) => Log(LogLevel.Warn, source, message);
        public static void LogInfo(string source, string message) => Log(LogLevel.Info, source, message);
        public static void LogDebug(string source, string message) => Log(LogLevel.Debug, source, message);

        public static void LogError(string source, string message, Exception ex)
            => Log(LogLevel.Error, source, message + Environment.NewLine + ex);

        public static void Log(LogLevel level, string source, string message)
        {
            if (level < MinimumLevel) return;

            try { Sink?.Invoke(level, source, message); }
            catch { /* 싱크 오류가 앱을 멈춰서는 안 된다 */ }

            string line = string.Format(CultureInfo.InvariantCulture, "{0:yyyy-MM-dd HH:mm:ss.fff} [{1,-5}] {2}: {3}{4}",
                DateTime.Now, level.ToString().ToUpperInvariant(), source, message, Environment.NewLine);

            lock (_lock)
            {
                try
                {
                    string file = CurrentFile();
                    File.AppendAllText(file, line, Encoding.UTF8);
                }
                catch
                {
                    // 로깅 실패가 애플리케이션을 중단시켜서는 안 된다.
                }
            }
        }

        private static string? _currentDir;

        private static string CurrentFile()
        {
            DateTime today = DateTime.Today;
            string dir = LogsDirectory; // 테스트가 UserDataPaths.OverrideRoot를 바꾸면 경로도 따라가야 한다
            if (_currentFile == null || _currentDate != today || _currentDir != dir)
            {
                Directory.CreateDirectory(dir);
                _currentDir = dir;
                _currentDate = today;
                _currentFile = Path.Combine(dir, today.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".log");
                Prune(dir, today);
            }
            return _currentFile;
        }

        private static void Prune(string dir, DateTime today)
        {
            try
            {
                foreach (string f in Directory.EnumerateFiles(dir, "*.log"))
                {
                    string name = Path.GetFileNameWithoutExtension(f);
                    if (DateTime.TryParseExact(name, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime d)
                        && (today - d).TotalDays > RetainDays)
                    {
                        File.Delete(f);
                    }
                }
            }
            catch { }
        }
    }
}
