using System;
using System.Threading;
using System.Threading.Tasks;
using KetworkScanner.Updates;
using Velopack;
using Velopack.Sources;

namespace KetworkScanner.Avalonia;

public enum UpdateState { Idle, Checking, Available, Downloading, Ready, Failed, UpToDate, NotInstalled }

// GitHub Releases에 첨부된 Velopack 피드(releases.{channel}.json)로 새 버전을 확인하고 내려받아 적용하는 도우미.
// 설정(UpdateSettings)에 따라 주기적으로 확인하고, 백그라운드로 내려받고, 앱 종료 시 자동 설치할 수 있다.
// 설치본(Velopack)이 아닌 실행(포터블 zip, dotnet run)에서는 GitHub Releases API로만 새 버전을 확인하고,
// 내려받는 대신 릴리스 페이지를 열어 준다(ExternalReleaseUrl).
public sealed class UpdateService
{

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
    private string _repo = GitHubReleases.DefaultRepo;
    private UpdateInfo? _pending;
    private string? _externalVersion;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UpdateState State { get; private set; } = UpdateState.Idle;
    public string? AvailableVersion => _pending?.TargetFullRelease.Version.ToString() ?? _externalVersion;
    // Velopack 설치본이면 true. false면 새 버전은 ExternalReleaseUrl(릴리스 페이지)로 안내한다.
    public bool IsInstalled { get { try { return _manager.IsInstalled; } catch { return false; } } }
    public string? ExternalReleaseUrl { get; private set; }
    // 마지막으로 피드를 확인한 시각(주기 확인의 기준). 한 번도 확인하지 않았으면 MinValue.
    public DateTime LastCheck { get; private set; } = DateTime.MinValue;

    // 상태가 바뀔 때마다(확인/다운로드 진행/완료/실패) 호출. UI 스레드가 아닐 수 있다.
    public event Action<UpdateState, int>? StateChanged;

    // beta 채널 여부는 설정을 읽은 뒤 SetPrerelease로 넘긴다.
    public UpdateService()
    {
        _manager = Create(_prerelease, _repo);
    }

    private static UpdateManager Create(bool prerelease, string repo)
        => new(new GithubSource("https://github.com/" + repo, null, prerelease), new UpdateOptions { ExplicitChannel = ChannelForCurrentRuntime() });

    // beta 채널/저장소 설정이 바뀌면 소스를 다시 만든다(이미 내려받은 업데이트는 유지).
    public void Configure(bool includePrerelease, string? repository)
    {
        string repo = string.IsNullOrWhiteSpace(repository) ? GitHubReleases.DefaultRepo : repository.Trim();
        if (includePrerelease == _prerelease && repo == _repo) return;
        _prerelease = includePrerelease;
        _repo = repo;
        _manager = Create(includePrerelease, repo);
        if (State is UpdateState.Available or UpdateState.UpToDate) { _pending = null; _externalVersion = null; ExternalReleaseUrl = null; Set(UpdateState.Idle); }
    }

    // 새 버전이 있으면 그 버전 문자열을, 없으면 null을 반환한다. 설치본이 아니면 릴리스 페이지만 찾는다(ExternalReleaseUrl).
    public async Task<string?> CheckAsync(CancellationToken ct = default)
    {
        if (!IsInstalled) return await CheckExternalAsync(ct).ConfigureAwait(false);
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

    // 설치본이 아닐 때: GitHub Releases API로 최신 태그를 읽어 현재 버전과 비교한다. 내려받지는 않는다.
    private async Task<string?> CheckExternalAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Set(UpdateState.Checking);
            LastCheck = DateTime.Now;
            ReleaseInfo? latest = await new GitHubReleases(_repo).GetLatestAsync(_prerelease, ct).ConfigureAwait(false);
            Version current = GitHubReleases.CurrentVersion();
            if (latest != null && latest.Version > current)
            {
                _externalVersion = latest.Version.ToString();
                ExternalReleaseUrl = string.IsNullOrEmpty(latest.HtmlUrl) ? $"https://github.com/{_repo}/releases/tag/{latest.Tag}" : latest.HtmlUrl;
                Set(UpdateState.Available);
                return _externalVersion;
            }
            _externalVersion = null;
            ExternalReleaseUrl = null;
            Set(UpdateState.UpToDate);
            return null;
        }
        catch
        {
            Set(UpdateState.Failed);
            throw;
        }
        finally { _gate.Release(); }
    }

    // 백그라운드 다운로드. 끝나면 Ready 상태가 되고, 종료 시 자동 설치(autoApplyOnExit)를 예약할 수 있다.
    // 설치본이 아니면 호출하지 말고 ExternalReleaseUrl을 열어 준다.
    public async Task DownloadAsync(bool autoApplyOnExit, CancellationToken ct = default)
    {
        if (_pending == null) throw new InvalidOperationException(IsInstalled ? "확인된 업데이트가 없습니다." : "설치본이 아니므로 릴리스 페이지에서 내려받아야 합니다.");
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

    private void Set(UpdateState state, int progress = 0)
    {
        State = state;
        try { StateChanged?.Invoke(state, progress); } catch { }
    }
}
