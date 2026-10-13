using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Updates
{
    public sealed record ReleaseAsset(string Name, string DownloadUrl, long Size);

    // HtmlUrl: 브라우저용 릴리스 페이지(설치본이 아닌 실행에서 "다운로드 페이지 열기"에 쓴다).
    public sealed record ReleaseInfo(Version Version, string Tag, bool Prerelease, DateTimeOffset PublishedAt, IReadOnlyList<ReleaseAsset> Assets, string HtmlUrl = "")
    {
        public ReleaseAsset? FindAsset(Func<string, bool> predicate) => Assets.FirstOrDefault(a => predicate(a.Name));
    }

    // GitHub Releases API에서 최신 릴리스를 읽는다(인증 없음, 분당 60회 제한 → 호출은 몇 시간에 한 번).
    public sealed class GitHubReleases
    {
        // 저장소가 이전 이름(knoxxr/…)에서 옮겨졌다. 설정(Update.Repository)으로 포크/사내 미러를 지정할 수 있다.
        public const string DefaultRepo = "MinaryHub/KetworkScanner";

        public string Repo => _repo;

        private readonly HttpClient _http;
        private readonly string _repo;

        public GitHubReleases(string? repo = null, HttpClient? http = null)
        {
            _repo = string.IsNullOrWhiteSpace(repo) ? DefaultRepo : repo;
            _http = http ?? CreateClient();
        }

        public static HttpClient CreateClient()
        {
            var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("KetworkScanner", "2"));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            return http;
        }

        // 초안(draft)은 제외하고, includePrerelease가 아니면 정식 릴리스만 본다. 버전은 태그 "v1.2.3"에서 읽는다.
        public async Task<ReleaseInfo?> GetLatestAsync(bool includePrerelease, CancellationToken ct)
        {
            using HttpResponseMessage resp = await _http.GetAsync($"https://api.github.com/repos/{_repo}/releases?per_page=15", ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            using JsonDocument doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            return ParseLatest(doc.RootElement, includePrerelease);
        }

        internal static ReleaseInfo? ParseLatest(JsonElement releases, bool includePrerelease)
        {
            ReleaseInfo? best = null;
            foreach (JsonElement r in releases.EnumerateArray())
            {
                if (r.TryGetProperty("draft", out var d) && d.GetBoolean()) continue;
                bool pre = r.TryGetProperty("prerelease", out var p) && p.GetBoolean();
                if (pre && !includePrerelease) continue;
                string tag = r.GetProperty("tag_name").GetString() ?? "";
                if (!TryParseVersion(tag, out Version? version) || version == null) continue;

                var assets = new List<ReleaseAsset>();
                if (r.TryGetProperty("assets", out var arr))
                {
                    foreach (JsonElement a in arr.EnumerateArray())
                    {
                        string name = a.GetProperty("name").GetString() ?? "";
                        string url = a.GetProperty("browser_download_url").GetString() ?? "";
                        long size = a.TryGetProperty("size", out var s) ? s.GetInt64() : 0;
                        if (name.Length > 0 && url.Length > 0) assets.Add(new ReleaseAsset(name, url, size));
                    }
                }
                DateTimeOffset published = r.TryGetProperty("published_at", out var pa) && pa.ValueKind == JsonValueKind.String
                    && DateTimeOffset.TryParse(pa.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dt) ? dt : DateTimeOffset.MinValue;

                string html = r.TryGetProperty("html_url", out var hu) && hu.ValueKind == JsonValueKind.String ? hu.GetString() ?? "" : "";
                var info = new ReleaseInfo(version, tag, pre, published, assets, html);
                if (best == null || info.Version > best.Version) best = info;
            }
            return best;
        }

        // "v1.2.3", "1.2.3", "v1.2.3-beta.1" → Version(1,2,3). 숫자 세 자리(또는 두 자리)만 본다.
        public static bool TryParseVersion(string? tag, out Version? version)
        {
            version = null;
            if (string.IsNullOrWhiteSpace(tag)) return false;
            string s = tag.Trim();
            if (s.StartsWith("v", StringComparison.OrdinalIgnoreCase)) s = s.Substring(1);
            int cut = s.IndexOfAny(new[] { '-', '+', ' ' });
            if (cut >= 0) s = s.Substring(0, cut);
            if (!Version.TryParse(s, out Version? v)) return false;
            version = new Version(v.Major, Math.Max(0, v.Minor), Math.Max(0, v.Build));
            return true;
        }

        public static Version CurrentVersion()
        {
            Version? v = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version;
            return v == null ? new Version(0, 0, 0) : new Version(v.Major, Math.Max(0, v.Minor), Math.Max(0, v.Build));
        }
    }
}
