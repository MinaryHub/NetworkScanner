using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KetworkScanner.Alerts;
using KetworkScanner.Notifications;
using KetworkScanner.Upload;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using KetworkScanner.Avalonia.Helpers;
using KetworkScanner.Avalonia.Views;

namespace KetworkScanner.Avalonia;

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
        AppLogger.LogInfo("KetworkScanner", "프로그램 시작");

        // 저장해 둔 컬럼 너비 복원, 종료 시 현재 너비 저장.
        AppSettingsData startup = _settingsView.GetCurrentSettings();

        // 설정 화면에서 예약한 이력 DB 복원은 엔진이 DB를 열기 전에 적용해야 한다.
        ApplyPendingHistoryRestore();

        // 엔진에는 실제 업로드 outbox + SQLite 이력을 연결하고, 동시성/상한은 설정값으로 시작한다.
        StartPassiveIfEnabled(startup);
        _services = ScanServices.CreateDefault(startup, passiveSnapshot: _passive == null ? null : () => _passive.SnapshotByIp());
        _ipListView.Initialize(this, _services, ScanOptions.FromSettings(startup));
        _ipListView.AlertsProcessed += OnAlertsProcessed;
        _ipListView.ScanStarted += OnScanStarted;
        _ipListView.ScanFinished += OnScanFinished;
        _ipListView.ProfileChanged += _settingsView.SetScanProfile;
        _settingsView.SettingsSaved += data =>
        {
            _ipListView.ApplyOptions(ScanOptions.FromSettings(data));
            _ipListView.SetProfile(data.ScanProfile);
            _historyView.SetRetentionDays(data.HistoryRetentionDays);
        };
        _settingsView.SetHistory(_services.History);
        _historyView.Initialize(_services.History);
        _historyView.SetRetentionDays(startup.HistoryRetentionDays);
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
            // 종료 시 자동 설치는 다운로드가 끝날 때 UpdateService.DownloadAsync(autoApplyOnExit)가 이미 예약한다.
            AppLogger.LogInfo("KetworkScanner", "프로그램 종료");
        };

        if (startup.LoadLatestFileOnStartup)
        {
            _ipListView.GetLatestFilePath(GetSystemName());
        }

        InitUpdates(startup);
        InitReferenceData(startup);
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
            AppLogger.LogError("KetworkScanner", "usage notice failed: " + ex.Message);
        }
    }

    // 마커 파일(history.restore)이 있으면 백업을 history.db 자리에 복사한다. 실패해도 앱은 그대로 뜬다(로그만).
    private void ApplyPendingHistoryRestore()
    {
        try
        {
            string? source = HistoryRestore.ApplyPending();
            if (source != null) AppLogger.LogInfo("KetworkScanner", string.Format(Localization.T("msg.history.restored"), source));
        }
        catch (Exception ex)
        {
            AppLogger.LogError("KetworkScanner", string.Format(Localization.T("msg.history.restore.failed"), ex.Message), ex);
        }
    }

    // 알림 운영 규칙을 거친 변화만 설정된 알림 채널(웹훅/syslog/메일)로 보낸다. 화면 경고/로그는 IPListView가
    // ScanChangesDetected에서 따로 처리한다. 실패해도 스캔/UI에는 영향을 주지 않는다.
    private void OnAlertsProcessed(AlertOutcome outcome)
    {
        UpdateAlertsLabel();
        if (outcome.Resolved > 0 || outcome.Suppressed.Count > 0)
        {
            AppLogger.LogInfo("KetworkScanner",
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
                if (sent > 0) AppLogger.LogInfo("KetworkScanner", string.Format(Localization.T("msg.notify.sent"), sent));
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", string.Format(Localization.T("msg.notify.failed"), ex.Message), ex);
            }
        });
    }

    // 스캔이 시작되면 패시브 캡처에서 오래 조용한(1시간 이상) 호스트 항목을 버려, 지난 관측이 이번 스캔에서 "살아있음"으로 남지 않게 한다.
    private void OnScanStarted()
    {
        try { _passive?.Prune(TimeSpan.FromHours(1)); }
        catch (Exception ex) { AppLogger.LogWarn("KetworkScanner", "passive prune failed: " + ex.Message); }
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
        catch (Exception ex) { AppLogger.LogError("KetworkScanner", "alert count failed", ex); }

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
            int sent = await _services.Uploader.FlushAsync(upload, m => AppLogger.LogInfo("KetworkScanner", m), CancellationToken.None);
            if (sent > 0) AppLogger.LogInfo("KetworkScanner", string.Format(Localization.T("msg.outbox.flushed"), sent));
        }
        catch (Exception ex)
        {
            AppLogger.LogError("KetworkScanner", "outbox flush failed", ex);
        }
        Dispatcher.UIThread.Post(UpdateOutboxLabel);
    }

    // 사이드바에 "대기 중 업로드: N"을 표시한다(0이면 숨김).
    private void UpdateOutboxLabel()
    {
        int pending = 0;
        try { pending = _services?.Uploader?.Outbox.Count ?? 0; }
        catch (Exception ex) { AppLogger.LogError("KetworkScanner", "outbox count failed", ex); }

        TbOutbox.Text = $"{Localization.T("settings.outbox")}: {pending}";
        TbOutbox.IsVisible = pending > 0;
    }

    // ---- 자동 업데이트 ----
    // 설정(Update.*)에 따라 시작 시·주기적으로 확인하고, 백그라운드로 내려받고, 종료 시 자동 설치한다.
    // 설치본이 아닌 개발 실행(dotnet run)에서는 조용히 아무것도 하지 않는다. 마지막 확인 시각은 UpdateService.LastCheck가 갖는다.

    // 패시브 캡처(설정에서 켠 경우, libpcap/npcap + 권한 필요). 실패해도 앱은 그대로 동작한다.
    private KetworkScanner.Capture.PassiveListener? _listener;
    private KetworkScanner.Capture.ObservationAggregator? _passive;

    private void StartPassiveIfEnabled(AppSettingsData settings)
    {
        if (!settings.Discovery.PassiveListener) return;
        try
        {
            var (ok, reason) = KetworkScanner.Capture.PassiveListener.Probe();
            if (!ok) { AppLogger.LogWarn("KetworkScanner", "passive capture unavailable: " + reason); return; }
            _passive = new KetworkScanner.Capture.ObservationAggregator();
            _listener = new KetworkScanner.Capture.PassiveListener();
            _listener.Observed += obs => _passive.Add(obs);
            _listener.Start();
            Closing += (_, _) => { try { _listener.Dispose(); } catch { } };
        }
        catch (Exception ex) { AppLogger.LogWarn("KetworkScanner", "passive capture failed: " + ex.Message); }
    }

    private void InitUpdates(AppSettingsData settings)
    {
        _updateService.Configure(settings.Update.IncludePrerelease, settings.Update.Repository);
        _updateService.StateChanged += (state, progress) => Dispatcher.UIThread.Post(() => RenderUpdateState(state, progress));
        _settingsView.UpdateCheckRequested += () => _ = CheckForUpdatesAsync(manual: true);
        _settingsView.SettingsSaved += data => _updateService.Configure(data.Update.IncludePrerelease, data.Update.Repository);
        if (settings.Update.AutoCheck) _ = CheckForUpdatesAsync(manual: false);
    }

    private async System.Threading.Tasks.Task CheckForUpdatesAsync(bool manual)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        try
        {
            string? newVersion = await _updateService.CheckAsync();
            if (manual && newVersion == null)
                _settingsView.ShowUpdateStatus(Localization.T("update.uptodate"));
            if (newVersion == null) return;

            // 포터블/개발 실행은 내려받지 않고 버튼으로 릴리스 페이지를 열어 준다(자동으로 브라우저를 띄우지 않는다).
            if (settings.Update.AutoDownload && _updateService.IsInstalled)
                await _updateService.DownloadAsync(settings.Update.AutoApply);
        }
        catch (Exception ex)
        {
            // 오프라인 등 확인 실패는 치명적이지 않다 - 로그만 남긴다.
            AppLogger.LogInfo("KetworkScanner", "업데이트 확인/다운로드 실패: " + ex.Message);
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
                ToolTip.SetTip(BtnUpdate, string.Format(Localization.T(_updateService.IsInstalled ? "update.available" : "update.openpage"), v));
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
            UpdateState.Available => string.Format(Localization.T(_updateService.IsInstalled ? "update.available" : "update.openpage"), v)
                                     + (_updateService.IsInstalled ? "" : " " + Localization.T("update.notinstalled")),
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
                    if (!_updateService.IsInstalled)
                    {
                        // 설치본이 아니면 릴리스 페이지를 브라우저로 연다.
                        if (_updateService.ExternalReleaseUrl != null)
                            await Launcher.LaunchUriAsync(new Uri(_updateService.ExternalReleaseUrl));
                        BtnUpdate.IsEnabled = true;
                        break;
                    }
                    // 수동 다운로드도 설정의 '종료 시 설치'를 따른다(종료 시 따로 예약하는 코드는 없다).
                    if (_updateService.AvailableVersion != null)
                        await _updateService.DownloadAsync(autoApplyOnExit: _settingsView.GetCurrentSettings().Update.AutoApply);
                    break;
            }
        }
        catch (Exception ex)
        {
            AppLogger.LogError("KetworkScanner", "업데이트 실패: " + ex.Message);
            TbUpdate.Text = Localization.T("update.failed");
            BtnUpdate.IsEnabled = true;
        }
    }

    // ---- 참조 데이터 자동 갱신(참고 포트 목록·OUI·취약점 규칙) ----
    // 시작 시와 설정 주기마다 저장소의 data/refdata.json을 확인해 새 파일을 사용자 폴더에 내려받고, 목록/테이블/규칙을 다시 읽는다.
    private KetworkScanner.Updates.ReferenceDataUpdater _refData = new();
    private bool _refDataBusy;

    private static KetworkScanner.Updates.ReferenceDataUpdater CreateRefDataUpdater(AppSettingsData s)
        => new(string.IsNullOrWhiteSpace(s.ReferenceData.SourceUrl)
            ? KetworkScanner.Updates.ReferenceDataUpdater.DefaultSourceUrl(s.Update.Repository)
            : s.ReferenceData.SourceUrl);

    private void InitReferenceData(AppSettingsData settings)
    {
        _refData = CreateRefDataUpdater(settings);
        _refPortListView.UpdateRequested += () => _ = CheckReferenceDataAsync(force: true);
        _settingsView.SettingsSaved += data => _refData = CreateRefDataUpdater(data);
        RenderReferenceDataStatus(null);
        if (settings.ReferenceData.AutoUpdate) _ = CheckReferenceDataAsync(force: false);
    }

    private async System.Threading.Tasks.Task CheckReferenceDataAsync(bool force)
    {
        if (_refDataBusy) return;
        _refDataBusy = true;
        _refPortListView.SetBusy(true);
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        try
        {
            _refPortListView.ShowStatus(Localization.T("refdata.checking"));
            var result = await _refData.CheckAndUpdateAsync(force, TimeSpan.FromHours(Math.Max(1, settings.ReferenceData.CheckIntervalHours)));
            if (result.Error != null)
            {
                AppLogger.LogWarn("RefData", "check failed: " + result.Error);
                RenderReferenceDataStatus(string.Format(Localization.T("refdata.failed"), result.Error));
                return;
            }
            if (result.Changed)
            {
                _refPortListView.LoadInfo();
                _ipListView.ReloadReferenceData();
                KetworkScanner.Vulnerability.RuleEngine.Reload();
                string names = string.Join(", ", result.Updated.Select(f => KetworkScanner.Updates.ReferenceDataUpdater.Label(f.Name) + " " + f.Version));
                AppLogger.LogInfo("RefData", "updated: " + names);
                RenderReferenceDataStatus(string.Format(Localization.T("refdata.updated"), names));
            }
            else RenderReferenceDataStatus(result.Checked ? Localization.T("refdata.uptodate") : null);
        }
        catch (Exception ex)
        {
            AppLogger.LogWarn("RefData", "check failed: " + ex.Message);
            RenderReferenceDataStatus(string.Format(Localization.T("refdata.failed"), ex.Message));
        }
        finally
        {
            _refDataBusy = false;
            _refPortListView.SetBusy(false);
        }
    }

    private void RenderReferenceDataStatus(string? message)
    {
        string line = KetworkScanner.Updates.ReferenceDataUpdater.Describe();
        _refPortListView.ShowStatus(message == null ? line : message + "  ·  " + line);
    }

    private void TickReferenceDataCheck(AppSettingsData settings)
    {
        if (!settings.ReferenceData.AutoUpdate || _refDataBusy) return;
        if (!_refData.IsDue(TimeSpan.FromHours(Math.Max(1, settings.ReferenceData.CheckIntervalHours)))) return;
        _ = CheckReferenceDataAsync(force: false);
    }

    // 1분 타이머에서 호출: 설정된 주기마다 자동 확인.
    private void TickUpdateCheck(AppSettingsData settings, DateTime now)
    {
        if (!settings.Update.AutoCheck) return;
        if ((now - _updateService.LastCheck).TotalHours < Math.Max(1, settings.Update.CheckIntervalHours)) return;
        if (_updateService.State is UpdateState.Downloading or UpdateState.Ready or UpdateState.Checking) return;
        _ = CheckForUpdatesAsync(manual: false);
    }

    private DateTime _lastMonitorScan = DateTime.MinValue;

    private void Timer_Tick(object? sender, EventArgs e)
    {
        AppSettingsData settings = _settingsView.GetCurrentSettings();
        DateTime now = DateTime.Now;
        TickUpdateCheck(settings, now);
        TickReferenceDataCheck(settings);

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
        IBrush accent = ThemeBrushes.Get("TealLightBrush", "#FF2DD4BF");
        IBrush activeBg = ThemeBrushes.Get("NavyRaisedBrush", "#FF16243A");

        foreach (Button nav in new[] { BtnIPList, BtnSetting, BtnPortInfo, BtnHistory, BtnGuide })
        {
            bool isActive = ReferenceEquals(nav, active);
            nav.Background = isActive ? activeBg : Brushes.Transparent;
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
