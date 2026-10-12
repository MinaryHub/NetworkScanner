using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner.Alerts;
using NetworkScanner.Notifications;
using NetworkScanner.Upload;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using NetworkScanner.Avalonia.Helpers;
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

        // 설정 화면에서 예약한 이력 DB 복원은 엔진이 DB를 열기 전에 적용해야 한다.
        ApplyPendingHistoryRestore();

        // 엔진에는 실제 업로드 outbox + SQLite 이력을 연결하고, 동시성/상한은 설정값으로 시작한다.
        _services = ScanServices.CreateDefault();
        _ipListView.Initialize(this, _services, ScanOptions.FromSettings(startup));
        _ipListView.AlertsProcessed += OnAlertsProcessed;
        _ipListView.ScanFinished += OnScanFinished;
        _ipListView.ProfileChanged += _settingsView.SetScanProfile;
        _settingsView.SettingsSaved += data =>
        {
            _ipListView.ApplyOptions(ScanOptions.FromSettings(data));
            _ipListView.SetProfile(data.ScanProfile);
        };
        _settingsView.SetHistory(_services.History);
        _historyView.Initialize(_services.History);
        _historyView.AlertsChanged += UpdateAlertsLabel;
        ContentArea.Content = _ipListView;
        SetActiveNav(BtnIPList);
        UpdateAlertsLabel();

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
            // 내려받아 둔 업데이트가 있고 자동 설치가 켜져 있으면 종료 직후 조용히 설치된다.
            if (_updateService.State == UpdateState.Ready && _settingsView.GetCurrentSettings().Update.AutoApply)
                _updateService.ScheduleApplyOnExit();
            AppLogger.LogInfo("NetworkScanner", "프로그램 종료");
        };

        if (startup.LoadLatestFileOnStartup)
        {
            _ipListView.GetLatestFilePath(GetSystemName());
        }

        InitUpdates(startup);
        _ = FlushOutboxAsync();
        if (!startup.UsageNoticeAccepted) _ = ShowUsageNoticeAsync();
    }

    // 최초 실행 시 "허가된 네트워크만 스캔" 고지를 한 번 보여주고 확인 여부를 저장한다.
    private async Task ShowUsageNoticeAsync()
    {
        try
        {
            await Helpers.SimpleDialogs.ShowMessageAsync(this, Localization.T("notice.body"), Localization.T("notice.title"));
            _settingsView.MarkUsageNoticeAccepted();
            AppSettingsData data = AppSettingsStore.LoadSettings();
            data.UsageNoticeAccepted = true;
            AppSettingsStore.SaveSettings(data);
        }
        catch (Exception ex)
        {
            AppLogger.LogError("NetworkScanner", "usage notice failed: " + ex.Message);
        }
    }

    // 마커 파일(history.restore)이 있으면 백업을 history.db 자리에 복사한다. 실패해도 앱은 그대로 뜬다(로그만).
    private void ApplyPendingHistoryRestore()
    {
        try
        {
            string? source = HistoryRestore.ApplyPending();
            if (source != null) AppLogger.LogInfo("NetworkScanner", string.Format(Localization.T("msg.history.restored"), source));
        }
        catch (Exception ex)
        {
            AppLogger.LogError("NetworkScanner", string.Format(Localization.T("msg.history.restore.failed"), ex.Message), ex);
        }
    }

    // 알림 운영 규칙을 거친 변화만 설정된 알림 채널(웹훅/syslog/메일)로 보낸다. 화면 경고/로그는 IPListView가
    // ScanChangesDetected에서 따로 처리한다. 실패해도 스캔/UI에는 영향을 주지 않는다.
    private void OnAlertsProcessed(AlertOutcome outcome)
    {
        UpdateAlertsLabel();
        if (outcome.Resolved > 0 || outcome.Suppressed.Count > 0)
        {
            AppLogger.LogInfo("NetworkScanner",
                $"alerts: {outcome.Resolved} {Localization.T("change.resolved")}, {outcome.Suppressed.Count} {Localization.T("change.suppressed")}"
                + (outcome.InMaintenance ? " (maintenance)" : ""));
        }

        AppSettingsData settings = _settingsView.GetCurrentSettings();
        if (!settings.Notifications.Enabled || outcome.ChangesToNotify.Count == 0) return;
        string systemName = GetSystemName();
        IReadOnlyList<ScanChange> changes = outcome.ChangesToNotify;

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
        UpdateAlertsLabel();
        if (!_flushAfterScan) return;
        _flushAfterScan = false;
        _ = FlushOutboxAsync();
    }

    // 사이드바에 "열린 알림: N"을 표시한다(0이거나 이력 DB가 없으면 숨김).
    private void UpdateAlertsLabel()
    {
        int open = 0;
        try { open = _services?.History?.ListAlerts().Count ?? 0; }
        catch (Exception ex) { AppLogger.LogError("NetworkScanner", "alert count failed", ex); }

        TbAlerts.Text = string.Format(Localization.T("sidebar.alerts"), open);
        TbAlerts.IsVisible = open > 0;
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

    // ---- 자동 업데이트 ----
    // 설정(Update.*)에 따라 시작 시·주기적으로 확인하고, 백그라운드로 내려받고, 종료 시 자동 설치한다.
    // 설치본이 아닌 개발 실행(dotnet run)에서는 조용히 아무것도 하지 않는다.
    private DateTime _lastUpdateCheck = DateTime.MinValue;

    private void InitUpdates(AppSettingsData settings)
    {
        _updateService.SetPrerelease(settings.Update.IncludePrerelease);
        _updateService.StateChanged += (state, progress) => Dispatcher.UIThread.Post(() => RenderUpdateState(state, progress));
        _settingsView.UpdateCheckRequested += () => _ = CheckForUpdatesAsync(manual: true);
        _settingsView.SettingsSaved += data => _updateService.SetPrerelease(data.Update.IncludePrerelease);
        if (settings.Update.AutoCheck) _ = CheckForUpdatesAsync(manual: false);
    }

    private async System.Threading.Tasks.Task CheckForUpdatesAsync(bool manual)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        try
        {
            _lastUpdateCheck = DateTime.Now;
            string? newVersion = await _updateService.CheckAsync();
            if (manual && _updateService.State == UpdateState.NotInstalled)
                _settingsView.ShowUpdateStatus(Localization.T("update.notinstalled"));
            else if (manual && newVersion == null)
                _settingsView.ShowUpdateStatus(Localization.T("update.uptodate"));
            if (newVersion == null) return;

            if (settings.Update.AutoDownload)
                await _updateService.DownloadAsync(settings.Update.AutoApply);
        }
        catch (Exception ex)
        {
            // 오프라인 등 확인 실패는 치명적이지 않다 - 로그만 남긴다.
            AppLogger.LogInfo("NetworkScanner", "업데이트 확인/다운로드 실패: " + ex.Message);
            if (manual) _settingsView.ShowUpdateStatus(Localization.T("update.failed") + ": " + ex.Message);
        }
    }

    // 사이드바 버튼의 문구/표시를 상태에 맞춘다.
    private void RenderUpdateState(UpdateState state, int progress)
    {
        string? v = _updateService.AvailableVersion;
        bool autoApply = _settingsView.GetCurrentSettings().Update.AutoApply;
        switch (state)
        {
            case UpdateState.Available:
                TbUpdate.Text = $"{Localization.T("update.button")} v{v}";
                ToolTip.SetTip(BtnUpdate, string.Format(Localization.T("update.available"), v));
                BtnUpdate.IsVisible = true;
                BtnUpdate.IsEnabled = true;
                break;
            case UpdateState.Downloading:
                TbUpdate.Text = $"{Localization.T("update.downloading")} {progress}%";
                BtnUpdate.IsVisible = true;
                BtnUpdate.IsEnabled = false;
                break;
            case UpdateState.Ready:
                TbUpdate.Text = Localization.T("update.restart") + $" v{v}";
                ToolTip.SetTip(BtnUpdate, string.Format(Localization.T(autoApply ? "update.onexit" : "update.ready"), v));
                BtnUpdate.IsVisible = true;
                BtnUpdate.IsEnabled = true;
                break;
            case UpdateState.Failed:
                TbUpdate.Text = Localization.T("update.failed");
                BtnUpdate.IsVisible = true;
                BtnUpdate.IsEnabled = true;
                break;
            default:
                BtnUpdate.IsVisible = false;
                break;
        }
        _settingsView.ShowUpdateStatus(state switch
        {
            UpdateState.Checking => Localization.T("update.checking"),
            UpdateState.Available => string.Format(Localization.T("update.available"), v),
            UpdateState.Downloading => $"{Localization.T("update.downloading")} {progress}%",
            UpdateState.Ready => string.Format(Localization.T(autoApply ? "update.onexit" : "update.ready"), v),
            UpdateState.UpToDate => Localization.T("update.uptodate"),
            UpdateState.NotInstalled => Localization.T("update.notinstalled"),
            UpdateState.Failed => Localization.T("update.failed"),
            _ => "",
        });
    }

    private async void BtnUpdate_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            switch (_updateService.State)
            {
                case UpdateState.Ready:
                    _updateService.ApplyAndRestart();
                    break;
                case UpdateState.Available:
                case UpdateState.Failed:
                    BtnUpdate.IsEnabled = false;
                    if (_updateService.AvailableVersion == null) await _updateService.CheckAsync();
                    if (_updateService.AvailableVersion != null) await _updateService.DownloadAsync(autoApplyOnExit: false);
                    break;
            }
        }
        catch (Exception ex)
        {
            AppLogger.LogError("NetworkScanner", "업데이트 실패: " + ex.Message);
            TbUpdate.Text = Localization.T("update.failed");
            BtnUpdate.IsEnabled = true;
        }
    }

    // 1분 타이머에서 호출: 설정된 주기마다 자동 확인.
    private void TickUpdateCheck(AppSettingsData settings, DateTime now)
    {
        if (!settings.Update.AutoCheck) return;
        if ((now - _lastUpdateCheck).TotalHours < Math.Max(1, settings.Update.CheckIntervalHours)) return;
        if (_updateService.State is UpdateState.Downloading or UpdateState.Ready or UpdateState.Checking) return;
        _ = CheckForUpdatesAsync(manual: false);
    }

    private DateTime _lastMonitorScan = DateTime.MinValue;

    private void Timer_Tick(object? sender, EventArgs e)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        DateTime now = DateTime.Now;
        TickUpdateCheck(settings, now);

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
