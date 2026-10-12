using System.Globalization;
using NetworkScanner.Notifications;
using NetworkScanner.Updates;
using NetworkScanner.Upload;

namespace NetworkScanner.Service;

public sealed class SchedulerOptions
{
    public bool RunOnce { get; init; }
}

// settings.json을 주기적으로 다시 읽어(GUI에서 바꾼 설정 반영) 예약 시간/연속 모니터링에 맞춰 스캔한다.
// "마지막 실행 시각" 기준으로 판단하므로 절전/재시작으로 정각을 놓쳐도 그 시간대 안에 따라잡는다.
public sealed class ScanSchedulerWorker : BackgroundService
{
    private const string LastRunFile = "service-lastrun.txt";
    // 패시브 관측은 이 시간 넘게 조용한 호스트부터 버린다(스캔 전에 정리해 메모리가 무한히 늘지 않게).
    private static readonly TimeSpan PassiveMaxAge = TimeSpan.FromHours(24);

    private readonly ILogger<ScanSchedulerWorker> _log;
    private readonly SchedulerOptions _opts;
    private readonly IHostApplicationLifetime _lifetime;
    // 패시브 캡처(설정에서 켠 경우): 스캔 사이에도 ARP/DHCP/mDNS/SSDP 브로드캐스트를 들어 관측을 모은다.
    private NetworkScanner.Capture.PassiveListener? _listener;
    private NetworkScanner.Capture.ObservationAggregator? _passive;
    // 같은 설정 오류를 30초마다 반복해서 찍지 않도록 마지막으로 기록한 오류 문자열을 기억한다.
    private string? _lastSettingsProblem;

    public ScanSchedulerWorker(ILogger<ScanSchedulerWorker> log, SchedulerOptions opts, IHostApplicationLifetime lifetime)
    {
        _log = log;
        _opts = opts;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        AppLogger.Sink += (level, source, message) =>
        {
            if (level >= NetworkScanner.LogLevel.Error) _log.LogError("{Source}: {Message}", source, message);
            else if (level == NetworkScanner.LogLevel.Warn) _log.LogWarning("{Source}: {Message}", source, message);
        };
        AppSettingsStore.OnError = m => _log.LogError("{Message}", m);
        OUIInfo.OnError = m => _log.LogWarning("{Message}", m);
        PortReferenceLoader.OnError = m => _log.LogWarning("{Message}", m);
        PingTester.OnError = m => _log.LogWarning("{Message}", m);

        _log.LogInformation("NetworkScanner service started. Settings: {Path}", AppSettingsStore.SettingsPath);

        if (_opts.RunOnce)
        {
            // 한 번 스캔하고 끝나는 모드에서는 상주형 패시브 리스너를 띄우지 않는다.
            AppSettingsData? once = LoadValidSettings();
            if (once == null)
            {
                _log.LogError("settings.json is invalid; nothing scanned");
                Environment.ExitCode = 1;
            }
            else
            {
                await RunScanAsync(stoppingToken, scheduled: true, once);
            }
            _lifetime.StopApplication();
            return;
        }

        StartPassiveIfEnabled(AppSettingsStore.LoadSettings());

        DateTime lastScheduledHour = ReadLastRun();
        DateTime lastMonitor = DateTime.MinValue;
        DateTime lastUpdateCheck = DateTime.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                AppSettingsData? settings = LoadValidSettings();
                DateTime now = DateTime.Now;
                DateTime thisHour = new(now.Year, now.Month, now.Day, now.Hour, 0, 0);

                if (settings == null)
                {
                    // 잘못된 설정으로는 스캔하지 않는다. 사용자가 GUI/CLI로 고치면 다음 주기에 반영된다.
                }
                else if (settings.UseScheduling && settings.IsInScheduleHour(now.Hour) && thisHour > lastScheduledHour)
                {
                    await RunScanAsync(stoppingToken, scheduled: true, settings);
                    lastScheduledHour = thisHour;
                    WriteLastRun(thisHour);
                }
                else if (settings.ContinuousMonitoring && settings.MonitorIntervalMinutes >= 1
                         && (now - lastMonitor).TotalMinutes >= settings.MonitorIntervalMinutes)
                {
                    await RunScanAsync(stoppingToken, scheduled: false, settings);
                    lastMonitor = DateTime.Now;
                }

                // 자동 업데이트: 주기마다 확인하고(스캔 중이 아닐 때), 설정에 따라 내려받아 설치 후 재시작한다.
                if (settings != null && settings.Update.AutoCheck && (now - lastUpdateCheck).TotalHours >= Math.Max(1, settings.Update.CheckIntervalHours))
                {
                    lastUpdateCheck = now;
                    if (await TrySelfUpdateAsync(settings.Update, stoppingToken)) return;
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "scheduler loop error");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    // settings.json을 읽고 GUI와 같은 검사를 거친다. 문제가 있으면 (한 번만) 기록하고 null을 돌려준다.
    private AppSettingsData? LoadValidSettings()
    {
        AppSettingsData settings = AppSettingsStore.LoadSettings();
        List<string> problems = settings.Validate();
        if (problems.Count == 0)
        {
            if (_lastSettingsProblem != null) _log.LogInformation("settings.json is valid again");
            _lastSettingsProblem = null;
            return settings;
        }
        string joined = string.Join("; ", problems);
        if (joined != _lastSettingsProblem)
        {
            _log.LogError("settings.json is invalid, scans are skipped until it is fixed: {Problems}", joined);
            _lastSettingsProblem = joined;
        }
        return null;
    }

    // 새 버전을 확인하고(설정에 따라) 내려받아 적용한다. 적용했으면 true를 돌려주고 호출자는 프로세스를 끝낸다:
    // Unix는 종료 코드 75로 systemd/launchd가 재시작하게 하고, Windows는 도우미가 서비스를 다시 시작한다.
    private async Task<bool> TrySelfUpdateAsync(UpdateSettings update, CancellationToken ct)
    {
        try
        {
            var updater = new HeadlessUpdater();
            HeadlessUpdate? found = await updater.CheckAsync(GitHubReleases.CurrentVersion(), update.IncludePrerelease, ct);
            if (found == null) return false;
            _log.LogInformation("update available: {Version} ({Asset})", found.Version, found.Archive.Name);
            if (!update.AutoDownload) return false;

            string stage = await updater.DownloadAndStageAsync(found, requireChecksum: true, null, ct);
            _log.LogInformation("update {Version} downloaded and verified", found.Version);
            if (!update.AutoApply) return false;

            if (OperatingSystem.IsWindows())
            {
                HeadlessUpdater.LaunchWindowsApplyHelper(stage, HeadlessUpdater.InstallDirectory, "NetworkScanner");
            }
            else
            {
                int n = HeadlessUpdater.ApplyInPlace(stage, HeadlessUpdater.InstallDirectory);
                _log.LogInformation("update applied ({Count} files); restarting", n);
            }
            Environment.ExitCode = 75;
            _lifetime.StopApplication();
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning("self-update failed: {Message}", ex.Message);
            return false;
        }
    }

    private void StartPassiveIfEnabled(AppSettingsData settings)
    {
        if (!settings.Discovery.PassiveListener) return;
        try
        {
            var (ok, reason) = NetworkScanner.Capture.PassiveListener.Probe();
            if (!ok) { _log.LogWarning("passive capture unavailable: {Reason}", reason); return; }
            _passive = new NetworkScanner.Capture.ObservationAggregator();
            _listener = new NetworkScanner.Capture.PassiveListener();
            _listener.Observed += obs => _passive.Add(obs);
            if (_listener.Start()) _log.LogInformation("passive capture started on {Interface}", _listener.InterfaceName);
        }
        catch (Exception ex) { _log.LogWarning("passive capture failed to start: {Message}", ex.Message); }
    }

    public override void Dispose()
    {
        try { _listener?.Dispose(); } catch { }
        base.Dispose();
    }

    // 결과/알림에 쓰는 시스템 이름: 설정값이 비어 있으면 머신 이름.
    private static string ResolveSystemName(AppSettingsData settings)
        => string.IsNullOrWhiteSpace(settings.SystemName) ? Environment.MachineName : settings.SystemName;

    private async Task RunScanAsync(CancellationToken ct, bool scheduled, AppSettingsData settings)
    {
        Localization.Current = settings.Language;
        string systemName = ResolveSystemName(settings);

        // 오래된 패시브 관측을 비워 메모리가 계속 자라지 않게 한다.
        if (_passive != null)
        {
            int pruned = _passive.Prune(PassiveMaxAge);
            if (pruned > 0) _log.LogDebug("passive observations pruned: {Count}", pruned);
        }

        var oui = new OUIInfo();
        oui.LoadInfo();
        var (reserved, prohibited) = PortReferenceLoader.Load();
        var config = new ServiceConfig(settings, systemName, AppSettingsStore.LoadScanRanges(), reserved, prohibited);
        var services = ScanServices.CreateDefault(settings, passiveSnapshot: _passive == null ? null : () => _passive.SnapshotByIp());
        var engine = new ScanEngine(new IPInfoList(), oui, config, services, ScanOptions.FromSettings(settings));
        engine.Message += m => _log.LogInformation("{Message}", m);

        var notifier = new Notifier(settings.Notifications);
        engine.ScanChangesDetected += changes =>
        {
            foreach (var c in changes) _log.LogInformation("change: {Change}", ScanDiff.Describe(c));
        };
        // 알림 운영 규칙을 거친 것만 보낸다(중복 억제, 확인/스누즈, 점검 시간대).
        engine.AlertsProcessed += outcome =>
        {
            if (outcome.Resolved > 0 || outcome.Suppressed.Count > 0)
                _log.LogInformation("alerts: {Resolved} resolved, {Suppressed} suppressed, maintenance={Maint}", outcome.Resolved, outcome.Suppressed.Count, outcome.InMaintenance);
            if (outcome.ChangesToNotify.Count == 0) return;
            try { notifier.NotifyChangesAsync(systemName, outcome.ChangesToNotify, ct).GetAwaiter().GetResult(); }
            catch (Exception ex) { _log.LogWarning("notify failed: {Message}", ex.Message); }
        };

        using var reg = ct.Register(engine.ScanningStop);
        engine.InitFromConfig();
        bool started = scheduled ? engine.StartSchedulingScan(systemName) : engine.StartRefreshAllRange(systemName);
        if (!started)
        {
            _log.LogWarning("scan could not be started ({Mode}); check the configured ranges and the MaxTargets limit", scheduled ? "scheduled" : "monitor");
        }
        else if (engine.Scanning != null)
        {
            await engine.Scanning;
        }

        // 밀린 업로드가 있으면 이 기회에 재전송한다.
        if (services.Uploader != null && settings.Upload.Enabled)
        {
            try { await services.Uploader.FlushAsync(settings.Upload, m => _log.LogInformation("{Message}", m), ct); }
            catch (Exception ex) { _log.LogWarning("outbox flush failed: {Message}", ex.Message); }
        }
        services.History?.Dispose();
    }

    private static DateTime ReadLastRun()
    {
        try
        {
            string p = UserDataPaths.Resolve(LastRunFile);
            if (File.Exists(p) && DateTime.TryParse(File.ReadAllText(p).Trim(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime d))
                return d;
        }
        catch { }
        return DateTime.MinValue;
    }

    private static void WriteLastRun(DateTime when)
    {
        try { File.WriteAllText(UserDataPaths.Resolve(LastRunFile), when.ToString("o", CultureInfo.InvariantCulture)); } catch { }
    }

    // settings.json을 그대로 IScanConfigProvider로 노출한다. 시스템 이름은 한 번 계산한 값을 쓴다.
    private sealed class ServiceConfig : IScanConfigProvider
    {
        private readonly AppSettingsData _s;
        private readonly string _systemName;
        private readonly ScanRangeList _ranges;
        private readonly List<RefPortInfo> _reserved, _prohibited;

        public ServiceConfig(AppSettingsData s, string systemName, ScanRangeList ranges, List<RefPortInfo> reserved, List<RefPortInfo> prohibited)
        {
            _s = s; _systemName = systemName; _ranges = ranges; _reserved = reserved; _prohibited = prohibited;
        }

        public string GetPortList() => _s.PortList;
        public UploadSettings GetUploadSettings() => _s.Upload;
        public string GetSystemName() => _systemName;
        public bool? GetUsePortChecking() => _s.UsePortChecking;
        public List<RefPortInfo> GetReservedPortList() => _reserved;
        public List<RefPortInfo> GetProhibitPortList() => _prohibited;
        public ScanRangeList GetScanRanges() => _ranges;
    }
}
