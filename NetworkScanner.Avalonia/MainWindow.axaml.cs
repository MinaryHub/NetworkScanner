using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Notifications;
using NetworkScanner.Upload;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using NetworkScanner.Avalonia.Views;

namespace NetworkScanner.Avalonia;

public partial class MainWindow : Window, IScanConfigProvider
{
    private readonly IPListView _ipListView = new();
    private readonly SettingsView _settingsView = new();
    private readonly RefPortListView _refPortListView = new();
    private readonly UserGuideView _userGuideView = new();
    private readonly HistoryView _historyView = new();
    private readonly DispatcherTimer _timer = new();
    private readonly UpdateService _updateService = new();
    private ScanServices? _services;

    // 예약 스캔이 마지막으로 실행된 "시각의 정시"(예: 2026-10-11 14:00). 같은 시간대에 두 번 돌지 않게 한다.
    private DateTime _lastScheduledHour = DateTime.MinValue;
    // 예약 스캔이 끝나면 outbox를 한 번 비우도록 표시한다.
    private bool _flushAfterScan;

    public MainWindow()
    {
        InitializeComponent();
    }

    private void Window_Loaded(object? sender, RoutedEventArgs e)
    {
        AppLogger.LogInfo("NetworkScanner", "프로그램 시작");

        // 저장해 둔 컬럼 너비 복원, 종료 시 현재 너비 저장.
        AppSettingsData startup = _settingsView.GetCurrentSettings();

        // 엔진에는 실제 업로드 outbox + SQLite 이력을 연결하고, 동시성/상한은 설정값으로 시작한다.
        _services = ScanServices.CreateDefault();
        _ipListView.Initialize(this, _services, ScanOptions.FromSettings(startup));
        _ipListView.ChangesDetected += OnScanChangesDetected;
        _ipListView.ScanFinished += OnScanFinished;
        _settingsView.SettingsSaved += data => _ipListView.ApplyOptions(ScanOptions.FromSettings(data));
        _historyView.Initialize(_services.History);
        ContentArea.Content = _ipListView;
        SetActiveNav(BtnIPList);

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        TbVersion.Text = "ver. " + (version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "unknown");

        _timer.Interval = TimeSpan.FromMinutes(1);
        _timer.Tick += Timer_Tick;
        _timer.Start();

        _ipListView.ApplyColumnWidths(startup.IpListColumnWidths);
        _settingsView.ApplyColumnWidths(startup.IpRangeColumnWidths);

        Closing += (_, _) =>
        {
            AppSettingsStore.SaveColumnLayout(_ipListView.GetColumnWidths(), _settingsView.GetColumnWidths());
            AppLogger.LogInfo("NetworkScanner", "프로그램 종료");
        };

        if (startup.LoadLatestFileOnStartup)
        {
            _ipListView.GetLatestFilePath(GetSystemName());
        }

        _ = CheckForUpdatesAsync();
        _ = FlushOutboxAsync();
    }

    // 변화 감지 시 설정된 알림 채널(웹훅/syslog/메일)로 보낸다. 실패해도 스캔/UI에는 영향을 주지 않는다.
    private void OnScanChangesDetected(IReadOnlyList<ScanChange> changes)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        if (!settings.Notifications.Enabled) return;
        string systemName = GetSystemName();

        _ = Task.Run(async () =>
        {
            try
            {
                int sent = await new Notifier(settings.Notifications).NotifyChangesAsync(systemName, changes, CancellationToken.None);
                if (sent > 0) AppLogger.LogInfo("NetworkScanner", string.Format(Localization.T("msg.notify.sent"), sent));
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.notify.failed"), ex.Message), ex);
            }
        });
    }

    private void OnScanFinished()
    {
        UpdateOutboxLabel();
        if (!_flushAfterScan) return;
        _flushAfterScan = false;
        _ = FlushOutboxAsync();
    }

    // 전송 실패로 outbox에 밀린 결과 파일을 다시 보낸다(시작 시, 예약 스캔 후).
    private async Task FlushOutboxAsync()
    {
        if (_services?.Uploader == null) return;
        UploadSettings upload = _settingsView.GetCurrentSettings().Upload;
        if (!upload.Enabled || _services.Uploader.Outbox.Count == 0) { UpdateOutboxLabel(); return; }

        try
        {
            int sent = await _services.Uploader.FlushAsync(upload, m => AppLogger.LogInfo("NetworkScanner", m), CancellationToken.None);
            if (sent > 0) AppLogger.LogInfo("NetworkScanner", string.Format(Localization.T("msg.outbox.flushed"), sent));
        }
        catch (Exception ex)
        {
            AppLogger.LogError("NetworkScanner", "outbox flush failed", ex);
        }
        Dispatcher.UIThread.Post(UpdateOutboxLabel);
    }

    // 사이드바에 "대기 중 업로드: N"을 표시한다(0이면 숨김).
    private void UpdateOutboxLabel()
    {
        int pending = 0;
        try { pending = _services?.Uploader?.Outbox.Count ?? 0; }
        catch (Exception ex) { AppLogger.LogError("NetworkScanner", "outbox count failed", ex); }

        TbOutbox.Text = $"{Localization.T("settings.outbox")}: {pending}";
        TbOutbox.IsVisible = pending > 0;
    }

    // GitHub Releases에서 새 버전을 확인하고, 있으면 사이드바의 업데이트 버튼을 노출한다.
    // 설치본이 아닌 개발 실행(dotnet run)에서는 조용히 아무것도 하지 않는다.
    private async System.Threading.Tasks.Task CheckForUpdatesAsync()
    {
        try
        {
            string? newVersion = await _updateService.CheckAsync();
            if (newVersion == null) return;

            TbUpdate.Text = $"{Localization.T("update.button")} v{newVersion}";
            ToolTip.SetTip(BtnUpdate, string.Format(Localization.T("update.available"), newVersion));
            BtnUpdate.IsVisible = true;
        }
        catch (Exception ex)
        {
            // 오프라인 등 확인 실패는 치명적이지 않다 - 로그만 남긴다.
            AppLogger.LogInfo("NetworkScanner", "업데이트 확인 실패: " + ex.Message);
        }
    }

    private async void BtnUpdate_Click(object? sender, RoutedEventArgs e)
    {
        BtnUpdate.IsEnabled = false;
        try
        {
            await _updateService.DownloadAndApplyAsync(percent =>
                Dispatcher.UIThread.Post(() =>
                    TbUpdate.Text = $"{Localization.T("update.downloading")} {percent}%"));
        }
        catch (Exception ex)
        {
            AppLogger.LogError("NetworkScanner", "업데이트 실패: " + ex.Message);
            TbUpdate.Text = Localization.T("update.failed");
            BtnUpdate.IsEnabled = true;
        }
    }

    private DateTime _lastMonitorScan = DateTime.MinValue;

    private void Timer_Tick(object? sender, EventArgs e)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        DateTime now = DateTime.Now;

        // 연속 모니터링: 지정한 분 간격마다 자동 재스캔(스케줄링과 독립적으로 동작).
        if (settings.ContinuousMonitoring
            && settings.MonitorIntervalMinutes >= 1
            && (now - _lastMonitorScan).TotalMinutes >= settings.MonitorIntervalMinutes
            && !_ipListView.IsScanning())
        {
            _lastMonitorScan = now;
            _ipListView.StartScan();
            return;
        }

        // 예약 스캔: 켜진 시간대에 아직 그 시간대의 스캔이 돌지 않았으면 실행한다.
        // "정각(0분)에만" 조건을 두지 않으므로 절전/지연으로 0분 틱을 놓쳐도 그 시간 안에 한 번은 돈다.
        if (!settings.UseScheduling) return;
        if (!settings.IsInScheduleHour(now.Hour)) return;
        DateTime thisHour = new DateTime(now.Year, now.Month, now.Day, now.Hour, 0, 0);
        if (_lastScheduledHour == thisHour) return;
        if (_ipListView.IsScanning()) return;

        _lastScheduledHour = thisHour;
        _flushAfterScan = true;
        _ipListView.SchedulingScan();
    }

    private void BtnIPList_Click(object? sender, RoutedEventArgs e)
    {
        ContentArea.Content = _ipListView;
        SetActiveNav(BtnIPList);
    }

    private void BtnSetting_Click(object? sender, RoutedEventArgs e)
    {
        ContentArea.Content = _settingsView;
        SetActiveNav(BtnSetting);
    }

    private void BtnPortInfo_Click(object? sender, RoutedEventArgs e)
    {
        ContentArea.Content = _refPortListView;
        SetActiveNav(BtnPortInfo);
    }

    private void BtnHistory_Click(object? sender, RoutedEventArgs e)
    {
        _historyView.Refresh();
        ContentArea.Content = _historyView;
        SetActiveNav(BtnHistory);
    }

    private void BtnGuide_Click(object? sender, RoutedEventArgs e)
    {
        ContentArea.Content = _userGuideView;
        SetActiveNav(BtnGuide);
    }

    // 사이드바에서 지금 어느 화면을 보고 있는지 좌측 강조선 + 배경 틴트로 표시한다.
    private void SetActiveNav(Button active)
    {
        var accent = (IBrush)Resources["AccentBrush"]!;
        var activeBg = (IBrush)Resources["SideActiveBackgroundBrush"]!;
        var inactiveBg = (IBrush)Resources["SideBackgroundBrush"]!;

        foreach (Button nav in new[] { BtnIPList, BtnSetting, BtnPortInfo, BtnHistory, BtnGuide })
        {
            bool isActive = ReferenceEquals(nav, active);
            nav.Background = isActive ? activeBg : inactiveBg;
            nav.BorderBrush = isActive ? accent : Brushes.Transparent;
        }
    }

    // IScanConfigProvider 구현 - SettingsView/RefPortListView에 위임한다.
    public string GetPortList() => _settingsView.GetCurrentSettings().PortList;

    public UploadSettings GetUploadSettings() => _settingsView.GetCurrentSettings().Upload;
    public string GetSystemName() => _settingsView.GetSystemName();
    public bool? GetUsePortChecking() => _settingsView.GetCurrentSettings().UsePortChecking;
    public List<RefPortInfo> GetReservedPortList() => _refPortListView.ReservedPortList;
    public List<RefPortInfo> GetProhibitPortList() => _refPortListView.ProhibitPortList;
    public ScanRangeList GetScanRanges() => _settingsView.ScanRanges;
}
