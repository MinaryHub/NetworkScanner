using System;
using System.Threading;
using System.Threading.Tasks;
using Velopack;
using Velopack.Sources;

namespace NetworkScanner.Avalonia;

public enum UpdateState { Idle, Checking, Available, Downloading, Ready, Failed, UpToDate, NotInstalled }

// GitHub Releases에 첨부된 Velopack 피드(releases.{channel}.json)로 새 버전을 확인하고 내려받아 적용하는 도우미.
// 설정(UpdateSettings)에 따라 주기적으로 확인하고, 백그라운드로 내려받고, 앱 종료 시 자동 설치할 수 있다.
public sealed class UpdateService
{
    private const string RepoUrl = "https://github.com/" + NetworkScanner.Updates.GitHubReleases.DefaultRepo;

    // release.yml의 --channel 과 반드시 일치해야 한다. 기본 채널(win/osx/linux)은 x64(macOS는 arm64) 빌드가 쓰고,
    // 그 외 아키텍처는 RID 이름을 채널로 쓴다. 다른 채널의 피드를 보면 잘못된 아키텍처 바이너리로 업데이트된다.
    internal static string ChannelForCurrentRuntime()
    {
        string os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux";
        var arch = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture;
        bool isDefault = os == "osx"
            ? arch == System.Runtime.InteropServices.Architecture.Arm64
            : arch == System.Runtime.InteropServices.Architecture.X64;
        return isDefault ? os : $"{os}-{arch.ToString().ToLowerInvariant()}";
    }

    private UpdateManager _manager;
    private bool _prerelease;
    private UpdateInfo? _pending;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UpdateState State { get; private set; } = UpdateState.Idle;
    public string? AvailableVersion => _pending?.TargetFullRelease.Version.ToString();
    public bool IsInstalled => _manager.IsInstalled;
    public DateTime LastCheck { get; private set; } = DateTime.MinValue;

    // 상태가 바뀔 때마다(확인/다운로드 진행/완료/실패) 호출. UI 스레드가 아닐 수 있다.
    public event Action<UpdateState, int>? StateChanged;

    public UpdateService(bool includePrerelease = false)
    {
        _prerelease = includePrerelease;
        _manager = Create(includePrerelease);
    }

    private static UpdateManager Create(bool prerelease)
        => new(new GithubSource(RepoUrl, null, prerelease), new UpdateOptions { ExplicitChannel = ChannelForCurrentRuntime() });

    // beta 채널 설정이 바뀌면 소스를 다시 만든다(이미 내려받은 업데이트는 유지).
    public void SetPrerelease(bool includePrerelease)
    {
        if (includePrerelease == _prerelease) return;
        _prerelease = includePrerelease;
        _manager = Create(includePrerelease);
        if (State is UpdateState.Available or UpdateState.UpToDate) { _pending = null; Set(UpdateState.Idle); }
    }

    // 새 버전이 있으면 그 버전 문자열을, 없거나 설치본이 아니면(dotnet run 등) null을 반환한다.
    public async Task<string?> CheckAsync(CancellationToken ct = default)
    {
        if (!_manager.IsInstalled) { Set(UpdateState.NotInstalled); return null; }
        if (State is UpdateState.Downloading or UpdateState.Ready) return AvailableVersion;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Set(UpdateState.Checking);
            LastCheck = DateTime.Now;
            _pending = await _manager.CheckForUpdatesAsync().ConfigureAwait(false);
            Set(_pending == null ? UpdateState.UpToDate : UpdateState.Available);
            return AvailableVersion;
        }
        catch
        {
            Set(UpdateState.Failed);
            throw;
        }
        finally { _gate.Release(); }
    }

    // 백그라운드 다운로드. 끝나면 Ready 상태가 되고, 종료 시 자동 설치(autoApplyOnExit)를 예약할 수 있다.
    public async Task DownloadAsync(bool autoApplyOnExit, CancellationToken ct = default)
    {
        if (_pending == null) throw new InvalidOperationException("확인된 업데이트가 없습니다.");
        if (State == UpdateState.Ready) { if (autoApplyOnExit) ScheduleApplyOnExit(); return; }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Set(UpdateState.Downloading, 0);
            await _manager.DownloadUpdatesAsync(_pending, p => Set(UpdateState.Downloading, p), ct).ConfigureAwait(false);
            Set(UpdateState.Ready, 100);
            if (autoApplyOnExit) ScheduleApplyOnExit();
        }
        catch
        {
            Set(UpdateState.Failed);
            throw;
        }
        finally { _gate.Release(); }
    }

    // 앱이 정상 종료되면 조용히 설치한다(재시작하지 않음). 다음 실행부터 새 버전.
    public void ScheduleApplyOnExit()
    {
        if (_pending == null || State != UpdateState.Ready) return;
        try { _manager.WaitExitThenApplyUpdates(_pending, silent: true, restart: false); }
        catch (Exception ex) { AppLogger.LogWarn("Update", "apply-on-exit scheduling failed: " + ex.Message); }
    }

    // 지금 설치하고 재시작한다(Ready 상태일 때).
    public void ApplyAndRestart()
    {
        if (_pending == null || State != UpdateState.Ready) throw new InvalidOperationException("다운로드된 업데이트가 없습니다.");
        _manager.ApplyUpdatesAndRestart(_pending);
    }

    // 이전 버전과의 호환: 확인된 업데이트를 내려받고 바로 재시작.
    public async Task DownloadAndApplyAsync(Action<int>? progress = null)
    {
        if (_pending == null) throw new InvalidOperationException("확인된 업데이트가 없습니다.");
        if (State != UpdateState.Ready)
        {
            void Relay(UpdateState s, int p) { if (s == UpdateState.Downloading) progress?.Invoke(p); }
            StateChanged += Relay;
            try { await DownloadAsync(false).ConfigureAwait(false); }
            finally { StateChanged -= Relay; }
        }
        _manager.ApplyUpdatesAndRestart(_pending);
    }

    private void Set(UpdateState state, int progress = 0)
    {
        State = state;
        try { StateChanged?.Invoke(state, progress); } catch { }
    }
}
