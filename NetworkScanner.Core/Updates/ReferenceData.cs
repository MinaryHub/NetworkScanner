using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Updates
{
    // 참조 데이터(참고 포트 목록, OUI, 취약점 규칙) 한 파일의 매니페스트 항목. Version은 "yyyy-MM-dd"(문자열 비교로 신구 판단).
    public sealed class ReferenceFile
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long Size { get; set; }
    }

    // data/refdata.json. 저장소(원격)와 번들(실행 파일 옆), 사용자 폴더(갱신본) 세 곳에 같은 형식으로 있다.
    // 사용자 폴더의 사본은 LastCheck(마지막 확인 시각)도 갖는다.
    public sealed class ReferenceManifest
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public string Generated { get; set; } = "";
        public List<ReferenceFile> Files { get; set; } = new();
        public DateTime? LastCheck { get; set; }

        public ReferenceFile? Find(string name) => Files.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));

        public void Upsert(ReferenceFile file)
        {
            ReferenceFile? existing = Find(file.Name);
            if (existing == null) Files.Add(new ReferenceFile { Name = file.Name, Version = file.Version, Sha256 = file.Sha256, Size = file.Size });
            else { existing.Version = file.Version; existing.Sha256 = file.Sha256; existing.Size = file.Size; }
        }

        public static ReferenceManifest? Parse(string json)
        {
            try
            {
                ReferenceManifest? m = JsonSerializer.Deserialize<ReferenceManifest>(json, JsonOptions);
                if (m == null) return null;
                m.Files.RemoveAll(f => string.IsNullOrWhiteSpace(f.Name) || f.Name.Contains('/') || f.Name.Contains('\\') || f.Name.Contains(".."));
                return m;
            }
            catch (JsonException) { return null; }
        }

        public static ReferenceManifest? TryLoad(string path)
        {
            try { return File.Exists(path) ? Parse(File.ReadAllText(path, Encoding.UTF8)) : null; }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }

        public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);
    }

    public sealed record ReferenceUpdateResult(bool Checked, IReadOnlyList<ReferenceFile> Updated, IReadOnlyList<string> Skipped, string? Error)
    {
        public bool Changed => Updated.Count > 0;
        public static readonly ReferenceUpdateResult NotDue = new(false, Array.Empty<ReferenceFile>(), Array.Empty<string>(), null);
    }

    // 시작 시/주기적으로 저장소의 data/refdata.json을 읽어 번들보다 새 파일을 사용자 폴더(<userdata>/data)에 내려받는다.
    // 내려받은 파일은 SHA-256과 형식 검사를 통과해야만 쓰이고, DataPaths.Resolve가 번들보다 우선해서 찾는다.
    // 앱 업데이트로 번들이 더 새로워지면(버전 비교) 사용자 폴더 사본은 무시된다.
    public sealed class ReferenceDataUpdater
    {
        public const string ManifestFileName = "refdata.json";
        public const string FolderName = "data";
        public static readonly string[] ManagedFiles =
        {
            "reservedports.ini", "prohibitports.ini", Vulnerability.VulnRuleSet.FileName,
            OUIInfo.MalFileName, OUIInfo.MamFileName, OUIInfo.MasFileName,
        };

        // 테스트에서 번들 위치를 바꿀 수 있게 한다.
        internal static Func<string, string> BundledResolver = DataPaths.ResolveBundled;

        private readonly HttpClient _http;
        private readonly string _source;
        private readonly string _dir;

        public static string LocalDirectory => UserDataPaths.Resolve(FolderName);

        public static string DefaultSourceUrl(string? repo)
            => $"https://raw.githubusercontent.com/{(string.IsNullOrWhiteSpace(repo) ? GitHubReleases.DefaultRepo : repo.Trim())}/master/data/";

        public ReferenceDataUpdater(string? sourceUrl = null, HttpClient? http = null, string? localDir = null)
        {
            _source = string.IsNullOrWhiteSpace(sourceUrl) ? DefaultSourceUrl(null) : sourceUrl.Trim();
            if (!_source.EndsWith('/')) _source += "/";
            _http = http ?? GitHubReleases.CreateClient();
            _dir = localDir ?? LocalDirectory;
        }

        public string SourceUrl => _source;
        public string LocalDir => _dir;

        public ReferenceManifest? LocalManifest() => ReferenceManifest.TryLoad(Path.Combine(_dir, ManifestFileName));
        public static ReferenceManifest? BundledManifest() => ReferenceManifest.TryLoad(BundledResolver(ManifestFileName));

        public DateTime? LastCheck => LocalManifest()?.LastCheck;

        public bool IsDue(TimeSpan interval)
        {
            DateTime? last = LastCheck;
            return last == null || DateTime.Now - last.Value >= interval;
        }

        // 사용자 폴더의 갱신본이 번들보다 새(또는 같)으면 그 경로, 아니면 null(번들을 쓴다).
        public static string? PreferredLocalPath(string fileName, string? localDir = null)
        {
            string dir = localDir ?? LocalDirectory;
            string path = Path.Combine(dir, fileName);
            if (!File.Exists(path)) return null;
            ReferenceFile? local = ReferenceManifest.TryLoad(Path.Combine(dir, ManifestFileName))?.Find(fileName);
            if (local == null) return null;
            ReferenceFile? bundled = BundledManifest()?.Find(fileName);
            if (bundled != null && string.CompareOrdinal(bundled.Version, local.Version) > 0) return null;
            return path;
        }

        // 실제로 쓰이는 파일별 버전(갱신본 또는 번들). 번들 매니페스트가 없으면 버전은 ""이다.
        public static IReadOnlyList<ReferenceFile> EffectiveVersions(string? localDir = null)
        {
            string dir = localDir ?? LocalDirectory;
            ReferenceManifest? local = ReferenceManifest.TryLoad(Path.Combine(dir, ManifestFileName));
            ReferenceManifest? bundled = BundledManifest();
            var result = new List<ReferenceFile>();
            foreach (string name in ManagedFiles)
            {
                ReferenceFile? l = PreferredLocalPath(name, dir) != null ? local?.Find(name) : null;
                ReferenceFile? b = bundled?.Find(name);
                ReferenceFile? pick = l ?? b;
                if (pick != null) result.Add(pick);
            }
            return result;
        }

        // 사람이 읽을 요약: "예약 포트 2026-10-13 · 백도어 포트 2026-10-13 · … · 마지막 확인 10-13 14:05"
        public static string Describe(string? localDir = null)
        {
            string dir = localDir ?? LocalDirectory;
            var parts = new List<string>();
            foreach (ReferenceFile f in EffectiveVersions(dir))
            {
                if (f.Name.StartsWith("ouiinfo-", StringComparison.OrdinalIgnoreCase)) continue; // MA-M/MA-S는 OUI와 같이 움직인다
                parts.Add(Label(f.Name) + " " + (f.Version.Length == 0 ? "?" : f.Version));
            }
            DateTime? last = ReferenceManifest.TryLoad(Path.Combine(dir, ManifestFileName))?.LastCheck;
            parts.Add(string.Format(Localization.T("refdata.checked"), last?.ToString("MM-dd HH:mm", CultureInfo.InvariantCulture) ?? Localization.T("refdata.never")));
            return string.Join("  ·  ", parts);
        }

        public static string Label(string fileName) => fileName.ToLowerInvariant() switch
        {
            "reservedports.ini" => Localization.T("refdata.file.reservedports"),
            "prohibitports.ini" => Localization.T("refdata.file.prohibitports"),
            "vulnrules.json" => Localization.T("refdata.file.vulnrules"),
            "ouiinfo.ini" => "OUI",
            "ouiinfo-mam.ini" => "OUI MA-M",
            "ouiinfo-mas.ini" => "OUI MA-S",
            _ => fileName,
        };

        // force=false면 interval이 지났을 때만 확인한다. 네트워크 실패는 Error로 돌려주고(예외 없음) LastCheck는 갱신한다.
        public async Task<ReferenceUpdateResult> CheckAndUpdateAsync(bool force, TimeSpan interval, CancellationToken ct = default)
        {
            if (!force && !IsDue(interval)) return ReferenceUpdateResult.NotDue;

            Directory.CreateDirectory(_dir);
            ReferenceManifest local = LocalManifest() ?? new ReferenceManifest();
            ReferenceManifest remote;
            try
            {
                string json = await _http.GetStringAsync(_source + ManifestFileName, ct).ConfigureAwait(false);
                remote = ReferenceManifest.Parse(json) ?? throw new InvalidDataException("invalid manifest");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                local.LastCheck = DateTime.Now;
                Save(local);
                return new ReferenceUpdateResult(true, Array.Empty<ReferenceFile>(), Array.Empty<string>(), ex.Message);
            }

            ReferenceManifest? bundled = BundledManifest();
            var updated = new List<ReferenceFile>();
            var skipped = new List<string>();
            foreach (ReferenceFile remoteFile in remote.Files)
            {
                ct.ThrowIfCancellationRequested();
                if (!ManagedFiles.Contains(remoteFile.Name, StringComparer.OrdinalIgnoreCase)) continue;

                string currentPath = PreferredLocalPath(remoteFile.Name, _dir) ?? BundledResolver(remoteFile.Name);
                string? currentSha = File.Exists(currentPath) ? HashFile(currentPath) : null;
                if (string.Equals(currentSha, remoteFile.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    if (currentPath.StartsWith(_dir, StringComparison.Ordinal)) local.Upsert(remoteFile);
                    continue;
                }
                ReferenceFile? b = bundled?.Find(remoteFile.Name);
                if (b != null && string.CompareOrdinal(b.Version, remoteFile.Version) > 0) continue; // 번들이 더 새롭다

                try
                {
                    byte[] bytes = await _http.GetByteArrayAsync(_source + remoteFile.Name, ct).ConfigureAwait(false);
                    if (remoteFile.Size > 0 && bytes.LongLength != remoteFile.Size) throw new InvalidDataException("size mismatch");
                    string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                    if (!string.Equals(sha, remoteFile.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("checksum mismatch");

                    string tmp = Path.Combine(_dir, remoteFile.Name + ".tmp");
                    await File.WriteAllBytesAsync(tmp, bytes, ct).ConfigureAwait(false);
                    if (!Validate(remoteFile.Name, tmp)) { File.Delete(tmp); throw new InvalidDataException("content validation failed"); }
                    File.Move(tmp, Path.Combine(_dir, remoteFile.Name), overwrite: true);
                    local.Upsert(remoteFile);
                    updated.Add(remoteFile);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    skipped.Add(remoteFile.Name + ": " + ex.Message);
                    AppLogger.LogWarn("RefData", $"{remoteFile.Name} not updated: {ex.Message}");
                }
            }

            local.Generated = remote.Generated;
            local.LastCheck = DateTime.Now;
            Save(local);
            return new ReferenceUpdateResult(true, updated, skipped, null);
        }

        private void Save(ReferenceManifest local)
        {
            try
            {
                Directory.CreateDirectory(_dir);
                File.WriteAllText(Path.Combine(_dir, ManifestFileName), local.ToJson(), new UTF8Encoding(false));
            }
            catch (Exception ex) { AppLogger.LogWarn("RefData", "manifest save failed: " + ex.Message); }
        }

        public static string HashFile(string path)
        {
            using FileStream fs = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }

        // 내려받은 파일이 기대한 형식인지 최소한으로 확인한다(잘못된 파일로 목록이 비는 것을 막는다).
        public static bool Validate(string fileName, string path)
        {
            try
            {
                switch (fileName.ToLowerInvariant())
                {
                    case "reservedports.ini":
                        return CountLines(path, new Regex(@"^(TCP|UDP),\d+,", RegexOptions.IgnoreCase)) >= 1000;
                    case "prohibitports.ini":
                        return CountLines(path, new Regex(@"^\d+,")) >= 50;
                    case "vulnrules.json":
                        return Vulnerability.VulnRuleSet.Parse(File.ReadAllText(path, Encoding.UTF8)).Rules.Count > 0;
                    case "ouiinfo.ini":
                        return CountLines(path, new Regex(@"\(hex\)")) >= 10000;
                    case "ouiinfo-mam.ini":
                    case "ouiinfo-mas.ini":
                        return CountLines(path, new Regex(@"\(hex\)")) >= 1000;
                    default:
                        return false;
                }
            }
            catch { return false; }
        }

        private static int CountLines(string path, Regex pattern)
        {
            int n = 0;
            foreach (string line in File.ReadLines(path, Encoding.UTF8)) if (pattern.IsMatch(line)) n++;
            return n;
        }
    }
}
