using Avalonia;
using System;
using System.IO;
using System.Threading.Tasks;
using Velopack;

namespace NetworkScanner.Avalonia;

class Program
{
    private const string LogSource = "NetworkScanner";

    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static int Main(string[] args)
    {
        // Velopack이 패키지(설치/제거/업데이트 등 OS별 라이프사이클 이벤트)를 올바르게 처리하려면
        // 다른 초기화보다 먼저 호출되어야 한다. 자동 업데이트 기능을 아직 사용하지 않더라도,
        // vpk로 패키징된 실행 파일이 정상 동작하려면(특히 Windows 설치 시) 반드시 필요하다.
        VelopackApp.Build().Run();

        // 어디서 터지든 로그에 남긴다: 비UI 스레드의 처리되지 않은 예외, 관찰되지 않은 Task 예외.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Exception ex = e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString() ?? "unknown");
            AppLogger.LogError(LogSource, "unhandled", ex);
            if (e.IsTerminating) WriteCrashFile(ex);
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AppLogger.LogError(LogSource, "unhandled", e.Exception);
            e.SetObserved();
        };

        try
        {
            // UI를 만들기 전에 설정에서 언어를 읽어 적용한다(마크업 확장이 로드 시점에 이 값을 참조).
            Localization.Current = AppSettingsStore.LoadSettings().Language;

            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            // UI 스레드까지 올라온 치명적 오류. 로그 + crash.txt를 남기고 비정상 종료 코드로 나간다.
            AppLogger.LogError(LogSource, "unhandled", ex);
            WriteCrashFile(ex);
            return 1;
        }
    }

    // 로그 폴더에 crash.txt를 남긴다(OS 불문). 로그 폴더 자체를 못 만들면 조용히 포기한다.
    internal static void WriteCrashFile(Exception ex)
    {
        try
        {
            string dir = AppLogger.LogsDirectory;
            Directory.CreateDirectory(dir);
            string text = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {Localization.T("app.crash")} {dir}{Environment.NewLine}{ex}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(dir, "crash.txt"), text);
        }
        catch
        {
            // 크래시 처리 중의 2차 오류는 무시한다.
        }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
