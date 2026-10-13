using System;
using System.IO;
using System.Text.Json;
using KetworkScanner.Updates;

namespace KetworkScanner.Tests
{
    public class UpdaterTests
    {
        [Theory]
        [InlineData("v2.1.0", "2.1.0")]
        [InlineData("2.1", "2.1.0")]
        [InlineData("v2.2.0-beta.1", "2.2.0")]
        [InlineData("V3.0.1+build7", "3.0.1")]
        public void TryParseVersion_HandlesTagForms(string tag, string expected)
        {
            Assert.True(GitHubReleases.TryParseVersion(tag, out Version? v));
            Assert.Equal(Version.Parse(expected), v);
        }

        [Fact]
        public void TryParseVersion_RejectsGarbage()
        {
            Assert.False(GitHubReleases.TryParseVersion("latest", out _));
            Assert.False(GitHubReleases.TryParseVersion("", out _));
        }

        private const string ReleasesJson = """
        [
          { "tag_name": "v2.3.0", "draft": true, "prerelease": false, "assets": [] },
          { "tag_name": "v2.2.0-beta.1", "draft": false, "prerelease": true, "published_at": "2026-10-10T00:00:00Z",
            "assets": [ { "name": "netscan-2.2.0-osx-arm64.tar.gz", "browser_download_url": "https://x/beta.tar.gz", "size": 10 } ] },
          { "tag_name": "v2.1.0", "draft": false, "prerelease": false, "published_at": "2026-10-01T00:00:00Z", "html_url": "https://github.com/x/y/releases/tag/v2.1.0",
            "assets": [ { "name": "netscan-2.1.0-osx-arm64.tar.gz", "browser_download_url": "https://x/a.tar.gz", "size": 10 },
                        { "name": "netscan-2.1.0-win-x64.zip", "browser_download_url": "https://x/b.zip", "size": 10 },
                        { "name": "SHA256SUMS.txt", "browser_download_url": "https://x/sums", "size": 1 } ] },
          { "tag_name": "v2.0.0", "draft": false, "prerelease": false, "assets": [] }
        ]
        """;

        [Fact]
        public void ParseLatest_SkipsDraftsAndPrereleasesUnlessAllowed()
        {
            using JsonDocument doc = JsonDocument.Parse(ReleasesJson);
            ReleaseInfo? stable = GitHubReleases.ParseLatest(doc.RootElement, includePrerelease: false);
            Assert.NotNull(stable);
            Assert.Equal(new Version(2, 1, 0), stable!.Version);
            Assert.Equal(3, stable.Assets.Count);
            Assert.NotNull(stable.FindAsset(n => n == "SHA256SUMS.txt"));
            Assert.Equal("https://github.com/x/y/releases/tag/v2.1.0", stable.HtmlUrl);
            Assert.Equal("MinaryHub/KetworkScanner", GitHubReleases.DefaultRepo);
            Assert.Equal("acme/mirror", new GitHubReleases("acme/mirror", new System.Net.Http.HttpClient()).Repo);

            ReleaseInfo? beta = GitHubReleases.ParseLatest(doc.RootElement, includePrerelease: true);
            Assert.Equal(new Version(2, 2, 0), beta!.Version);
            Assert.True(beta.Prerelease);
        }

        [Fact]
        public void ParseChecksum_FindsHashForFileName()
        {
            string sums = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  netscan-2.1.0-win-x64.zip\n"
                        + "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 *release/netscan-2.1.0-osx-arm64.tar.gz\n";
            Assert.Equal("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", HeadlessUpdater.ParseChecksum(sums, "netscan-2.1.0-osx-arm64.tar.gz"));
            Assert.Null(HeadlessUpdater.ParseChecksum(sums, "other.zip"));
        }

        [Fact]
        public void ApplyInPlace_ReplacesFilesAndKeepsExecutableBit()
        {
            string root = Path.Combine(Path.GetTempPath(), "nstest-update-" + Guid.NewGuid().ToString("N"));
            string stage = Path.Combine(root, "stage"), install = Path.Combine(root, "install");
            Directory.CreateDirectory(Path.Combine(stage, "sub"));
            Directory.CreateDirectory(install);
            try
            {
                File.WriteAllText(Path.Combine(install, "netscan"), "old");
                File.WriteAllText(Path.Combine(stage, "netscan"), "new");
                File.WriteAllText(Path.Combine(stage, "sub", "data.ini"), "x");
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(Path.Combine(install, "netscan"), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

                int n = HeadlessUpdater.ApplyInPlace(stage, install);

                Assert.Equal(2, n);
                Assert.Equal("new", File.ReadAllText(Path.Combine(install, "netscan")));
                Assert.True(File.Exists(Path.Combine(install, "sub", "data.ini")));
                Assert.False(Directory.Exists(stage));
                if (!OperatingSystem.IsWindows())
                    Assert.True(File.GetUnixFileMode(Path.Combine(install, "netscan")).HasFlag(UnixFileMode.UserExecute));
            }
            finally { try { Directory.Delete(root, true); } catch { } }
        }

        [Fact]
        public void Rid_MatchesReleaseNaming()
        {
            string rid = HeadlessUpdater.Rid;
            Assert.Matches("^(win|osx|linux)-(x64|arm64|x86|arm)$", rid);
        }
    }
}
