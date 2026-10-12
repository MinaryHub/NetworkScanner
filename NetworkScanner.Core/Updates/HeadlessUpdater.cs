using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Updates
{
    public sealed record HeadlessUpdate(Version Version, string Tag, ReleaseAsset Archive, string? ExpectedSha256);

    // CLI(netscan)·서비스(netscan-service)용 자체 업데이트. GUI는 Velopack이 담당하고, 헤드리스 배포본은
    // 릴리스의 netscan-<ver>-<rid>.{zip,tar.gz}를 받아 SHA256SUMS.txt로 검증한 뒤 설치 폴더에 덮어쓴다.
    //  - Unix: 임시 파일에 쓴 뒤 rename으로 교체(실행 중인 바이너리도 inode가 달라 안전). 호출자가 프로세스를 끝내면 다음 실행부터 새 버전.
    //  - Windows: 실행 중인 exe는 덮어쓸 수 없으므로 "--apply-update <staged> <installDir> <pid>" 도우미 프로세스를 띄워
    //    부모 종료 후 교체하게 한다(서비스면 sc start로 재시작).
    public sealed class HeadlessUpdater
    {
        public const string ChecksumAssetName = "SHA256SUMS.txt";
        private readonly GitHubReleases _releases;
        private readonly HttpClient _http;

        public HeadlessUpdater(GitHubReleases? releases = null, HttpClient? http = null)
        {
            _http = http ?? GitHubReleases.CreateClient();
            _releases = releases ?? new GitHubReleases(null, _http);
        }

        public static string Rid =>
            (OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux")
            + "-" + RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

        public static string StagingRoot => UserDataPaths.Resolve("updates");

        // 현재 버전보다 새 릴리스가 있고 이 RID용 압축본이 붙어 있으면 그 정보를 돌려준다.
        public async Task<HeadlessUpdate?> CheckAsync(Version current, bool includePrerelease, CancellationToken ct)
        {
            ReleaseInfo? latest = await _releases.GetLatestAsync(includePrerelease, ct).ConfigureAwait(false);
            if (latest == null || latest.Version <= current) return null;

            string rid = Rid;
            ReleaseAsset? archive = latest.FindAsset(n => n.StartsWith("netscan-", StringComparison.OrdinalIgnoreCase)
                                                        && n.Contains("-" + rid + ".", StringComparison.OrdinalIgnoreCase)
                                                        && (n.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)));
            if (archive == null) return null;

            string? sha = null;
            ReleaseAsset? sums = latest.FindAsset(n => string.Equals(n, ChecksumAssetName, StringComparison.OrdinalIgnoreCase));
            if (sums != null)
            {
                try
                {
                    string text = await _http.GetStringAsync(sums.DownloadUrl, ct).ConfigureAwait(false);
                    sha = ParseChecksum(text, archive.Name);
                }
                catch (Exception ex) { AppLogger.LogWarn("Update", "checksum list unavailable: " + ex.Message); }
            }
            return new HeadlessUpdate(latest.Version, latest.Tag, archive, sha);
        }

        // "sha256  filename" / "sha256 *filename" 형식에서 해당 파일의 해시를 찾는다.
        internal static string? ParseChecksum(string sumsText, string fileName)
        {
            foreach (string raw in sumsText.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length < 66) continue;
                string hash = line.Substring(0, 64);
                string rest = line.Substring(64).TrimStart(' ', '*', '\t');
                if (string.Equals(Path.GetFileName(rest), fileName, StringComparison.OrdinalIgnoreCase)) return hash.ToLowerInvariant();
            }
            return null;
        }

        // 다운로드 → 해시 검증 → 압축 해제. 반환값은 스테이징 폴더(새 파일들이 들어 있음).
        public async Task<string> DownloadAndStageAsync(HeadlessUpdate update, bool requireChecksum, Action<int>? progress, CancellationToken ct)
        {
            Directory.CreateDirectory(StagingRoot);
            string archivePath = Path.Combine(StagingRoot, update.Archive.Name);
            string stageDir = Path.Combine(StagingRoot, update.Version.ToString(3));

            using (HttpResponseMessage resp = await _http.GetAsync(update.Archive.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
            {
                resp.EnsureSuccessStatusCode();
                long total = resp.Content.Headers.ContentLength ?? update.Archive.Size;
                await using Stream src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using FileStream dst = File.Create(archivePath);
                var buffer = new byte[81920];
                long done = 0;
                int read;
                while ((read = await src.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    await dst.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    done += read;
                    if (total > 0) progress?.Invoke((int)(done * 100 / total));
                }
            }

            string actual = await Sha256Async(archivePath, ct).ConfigureAwait(false);
            if (update.ExpectedSha256 != null)
            {
                if (!string.Equals(actual, update.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(archivePath);
                    throw new InvalidDataException($"checksum mismatch for {update.Archive.Name}: expected {update.ExpectedSha256}, got {actual}");
                }
            }
            else if (requireChecksum)
            {
                File.Delete(archivePath);
                throw new InvalidDataException("release has no SHA256SUMS.txt; refusing to install an unverified archive");
            }

            if (Directory.Exists(stageDir)) Directory.Delete(stageDir, true);
            Directory.CreateDirectory(stageDir);
            if (archivePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                ZipFile.ExtractToDirectory(archivePath, stageDir, overwriteFiles: true);
            else
            {
                await using FileStream fs = File.OpenRead(archivePath);
                await using var gz = new GZipStream(fs, CompressionMode.Decompress);
                await TarFile.ExtractToDirectoryAsync(gz, stageDir, overwriteFiles: true, ct).ConfigureAwait(false);
            }
            File.Delete(archivePath);
            return stageDir;
        }

        public static async Task<string> Sha256Async(string path, CancellationToken ct)
        {
            await using FileStream fs = File.OpenRead(path);
            byte[] hash = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        // Unix: 스테이징 폴더의 파일을 설치 폴더로 옮긴다(파일마다 임시 파일 → rename). 실행 권한은 원본과 같게 맞춘다.
        public static int ApplyInPlace(string stageDir, string installDir)
        {
            int n = 0;
            foreach (string src in Directory.EnumerateFiles(stageDir, "*", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(stageDir, src);
                string dst = Path.Combine(installDir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                string tmp = dst + ".new";
                File.Copy(src, tmp, overwrite: true);
                if (!OperatingSystem.IsWindows())
                {
                    try
                    {
                        UnixFileMode mode = File.Exists(dst) ? File.GetUnixFileMode(dst) : File.GetUnixFileMode(src);
                        File.SetUnixFileMode(tmp, mode);
                    }
                    catch { }
                }
                File.Move(tmp, dst, overwrite: true);
                n++;
            }
            try { Directory.Delete(stageDir, true); } catch { }
            return n;
        }

        // Windows: 도우미 프로세스를 띄운다. 부모(현재 프로세스)가 끝나면 교체하고, 서비스 이름이 주어지면 서비스를 다시 시작한다.
        public static void LaunchWindowsApplyHelper(string stageDir, string installDir, string? serviceName)
        {
            string exe = Environment.ProcessPath ?? throw new InvalidOperationException("process path unknown");
            // 도우미 자신도 교체 대상이므로 스테이징 폴더의 복사본을 실행한다.
            string helper = Path.Combine(stageDir, Path.GetFileName(exe));
            if (!File.Exists(helper)) helper = exe;
            var psi = new ProcessStartInfo(helper)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("--apply-update");
            psi.ArgumentList.Add(stageDir);
            psi.ArgumentList.Add(installDir);
            psi.ArgumentList.Add(Environment.ProcessId.ToString());
            if (!string.IsNullOrEmpty(serviceName)) psi.ArgumentList.Add(serviceName);
            Process.Start(psi);
        }

        // "--apply-update <stage> <install> <parentPid> [serviceName]" 로 실행된 도우미의 본체. 종료 코드를 돌려준다.
        public static int RunApplyHelper(string[] args)
        {
            if (args.Length < 3) return 2;
            string stage = args[0], install = args[1];
            if (int.TryParse(args[2], out int pid))
            {
                try { using Process p = Process.GetProcessById(pid); p.WaitForExit(60000); } catch { }
            }
            Thread.Sleep(500);
            for (int attempt = 0; attempt < 10; attempt++)
            {
                try
                {
                    ApplyInPlace(stage, install);
                    break;
                }
                catch (IOException) when (attempt < 9) { Thread.Sleep(1000); }
            }
            if (args.Length > 3 && OperatingSystem.IsWindows())
            {
                try { Process.Start(new ProcessStartInfo("sc.exe", $"start \"{args[3]}\"") { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(15000); } catch { }
            }
            return 0;
        }

        public static string InstallDirectory => AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    }
}
