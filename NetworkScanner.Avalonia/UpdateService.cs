using System;
using System.Threading.Tasks;
using Velopack;
using Velopack.Sources;

namespace NetworkScanner.Avalonia;

// GitHub Releases에 첨부된 Velopack 피드(releases.{os}.json)로 새 버전을 확인하고
// 다운로드/적용하는 도우미. release.yml이 만드는 릴리즈 자산을 그대로 사용한다.
public sealed class UpdateService
{
    private const string RepoUrl = "https://github.com/knoxxr/NetworkScanner";

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

    private readonly UpdateManager _manager = new(new GithubSource(RepoUrl, null, prerelease: false),
        new UpdateOptions { ExplicitChannel = ChannelForCurrentRuntime() });
    private UpdateInfo? _pending;

    // 새 버전이 있으면 그 버전 문자열을, 없거나 설치본이 아니면(dotnet run 등) null을 반환한다.
    public async Task<string?> CheckAsync()
    {
        if (!_manager.IsInstalled) return null;
        _pending = await _manager.CheckForUpdatesAsync().ConfigureAwait(false);
        return _pending?.TargetFullRelease.Version.ToString();
    }

    // CheckAsync가 새 버전을 찾은 뒤에만 호출할 것. 다운로드 후 앱을 재시작하며 적용한다.
    public async Task DownloadAndApplyAsync(Action<int>? progress = null)
    {
        if (_pending == null) throw new InvalidOperationException("확인된 업데이트가 없습니다.");
        await _manager.DownloadUpdatesAsync(_pending, progress).ConfigureAwait(false);
        _manager.ApplyUpdatesAndRestart(_pending);
    }
}
