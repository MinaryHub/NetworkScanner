using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace KetworkScanner.Avalonia;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Core의 각 모듈이 내는 오류 콜백을 파일 로거(AppLogger)에 연결한다.
        const string LogSource = "KetworkScanner";
        OUIInfo.OnError = message => AppLogger.LogError(LogSource, message);
        KetworkScanner.Network.IcmpPinger.OnError = message => AppLogger.LogError(LogSource, message);
        PortReferenceLoader.OnError = message => AppLogger.LogError(LogSource, message);
        AppSettingsStore.OnError = message => AppLogger.LogError(LogSource, message);
        WakeOnLan.OnError = message => AppLogger.LogError(LogSource, message);
        KetworkScanner.Secrets.SecretStoreDiagnostics.OnError = message => AppLogger.LogError(LogSource, message);

        // UI 스레드(디스패처)에서 처리되지 않은 예외: 이벤트 핸들러 하나의 오류로 앱 전체가 죽지 않도록
        // 로그에 남기고 계속 진행한다. (Dispatcher.UIThread는 플랫폼 초기화 뒤에만 안전하게 쓸 수 있어 여기서 건다.)
        Dispatcher.UIThread.UnhandledException += (_, e) =>
        {
            AppLogger.LogError(LogSource, "unhandled", e.Exception);
            Program.WriteCrashFile(e.Exception);
            e.Handled = true;
        };

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();
        }

        base.OnFrameworkInitializationCompleted();
    }
}