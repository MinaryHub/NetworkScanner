using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KetworkScanner.Updates;

namespace KetworkScanner.Tests
{
    // 참조 데이터 자동 갱신: 매니페스트 비교, SHA-256 검증, 번들/갱신본 우선순위, 주기.
    public class ReferenceDataTests : IDisposable
    {
        private readonly string _root;
        private readonly string _bundled;
        private readonly string _local;
        private readonly Func<string, string> _oldResolver;

        public ReferenceDataTests()
        {
            _root = Path.Combine(Path.GetTempPath(), "nsc-refdata-" + Guid.NewGuid().ToString("N"));
            _bundled = Path.Combine(_root, "bundled");
            _local = Path.Combine(_root, "data");
            Directory.CreateDirectory(_bundled);
            UserDataPaths.OverrideRoot = _root;
            _oldResolver = ReferenceDataUpdater.BundledResolver;
            ReferenceDataUpdater.BundledResolver = name => Path.Combine(_bundled, name);
        }

        public void Dispose()
        {
            ReferenceDataUpdater.BundledResolver = _oldResolver;
            UserDataPaths.OverrideRoot = null;
            try { Directory.Delete(_root, recursive: true); } catch { }
        }

        private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        private static byte[] PortsFile(int count, string suffix = "")
        {
            var sb = new StringBuilder();
            for (int i = 1; i <= count; i++) sb.Append("TCP,").Append(i).Append(",svc").Append(i).Append(suffix).Append('\n');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static byte[] BackdoorFile(int count)
        {
            var sb = new StringBuilder();
            for (int i = 1; i <= count; i++) sb.Append(1000 + i).Append(",trojan").Append(i).Append('\n');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private sealed class FakeHandler : HttpMessageHandler
        {
            public Dictionary<string, byte[]> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
            public int Requests;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                Requests++;
                string name = Path.GetFileName(request.RequestUri!.AbsolutePath);
                if (!Files.TryGetValue(name, out byte[]? body)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
            }
        }

        private static string Manifest(params (string name, string version, byte[] body)[] files)
        {
            var m = new ReferenceManifest { Generated = "2026-10-13" };
            foreach (var (name, version, body) in files) m.Files.Add(new ReferenceFile { Name = name, Version = version, Sha256 = Sha(body), Size = body.Length });
            return m.ToJson();
        }

        private void WriteBundled(string name, byte[] body) => File.WriteAllBytes(Path.Combine(_bundled, name), body);

        [Fact]
        public async Task Downloads_NewerFiles_VerifiesChecksum_AndPrefersThemOverBundled()
        {
            byte[] oldPorts = PortsFile(1200);
            byte[] newPorts = PortsFile(1300, "-new");
            byte[] backdoor = BackdoorFile(60);
            WriteBundled("reservedports.ini", oldPorts);
            WriteBundled("prohibitports.ini", backdoor);
            WriteBundled("refdata.json", Encoding.UTF8.GetBytes(Manifest(("reservedports.ini", "2026-01-01", oldPorts), ("prohibitports.ini", "2026-01-01", backdoor))));

            var handler = new FakeHandler();
            handler.Files["refdata.json"] = Encoding.UTF8.GetBytes(Manifest(("reservedports.ini", "2026-10-13", newPorts), ("prohibitports.ini", "2026-01-01", backdoor)));
            handler.Files["reservedports.ini"] = newPorts;
            var updater = new ReferenceDataUpdater("https://example.test/data/", new HttpClient(handler), _local);

            ReferenceUpdateResult result = await updater.CheckAndUpdateAsync(force: true, TimeSpan.FromHours(24));

            Assert.Null(result.Error);
            Assert.True(result.Changed);
            Assert.Single(result.Updated);
            Assert.Equal("reservedports.ini", result.Updated[0].Name);
            Assert.Empty(result.Skipped);
            Assert.Equal(2, handler.Requests); // 매니페스트 + 바뀐 파일 하나(백도어 목록은 같은 SHA라 받지 않음)

            string? preferred = ReferenceDataUpdater.PreferredLocalPath("reservedports.ini", _local);
            Assert.NotNull(preferred);
            Assert.Equal(newPorts, File.ReadAllBytes(preferred!));
            Assert.Null(ReferenceDataUpdater.PreferredLocalPath("prohibitports.ini", _local)); // 내려받지 않았으니 번들
            Assert.NotNull(updater.LastCheck);
            Assert.False(updater.IsDue(TimeSpan.FromHours(1)));

            // 실제 로더도 갱신본을 읽는다(DataPaths.Resolve → PreferredLocalPath).
            var (reserved, _) = PortReferenceLoader.Load();
            Assert.Equal(1300, reserved.Count);
        }

        [Fact]
        public async Task Rejects_ChecksumMismatch_AndInvalidContent()
        {
            byte[] bundledPorts = PortsFile(1200);
            WriteBundled("reservedports.ini", bundledPorts);
            byte[] tampered = PortsFile(1250);
            byte[] tooShort = PortsFile(10);
            var handler = new FakeHandler();
            var manifest = new ReferenceManifest { Generated = "2026-10-13" };
            manifest.Files.Add(new ReferenceFile { Name = "reservedports.ini", Version = "2026-10-13", Sha256 = Sha(PortsFile(1251)), Size = tampered.Length }); // 다른 SHA
            manifest.Files.Add(new ReferenceFile { Name = "prohibitports.ini", Version = "2026-10-13", Sha256 = Sha(tooShort), Size = tooShort.Length });   // 형식 검사 실패
            handler.Files["refdata.json"] = Encoding.UTF8.GetBytes(manifest.ToJson());
            handler.Files["reservedports.ini"] = tampered;
            handler.Files["prohibitports.ini"] = tooShort;
            var updater = new ReferenceDataUpdater("https://example.test/data/", new HttpClient(handler), _local);

            ReferenceUpdateResult result = await updater.CheckAndUpdateAsync(force: true, TimeSpan.Zero);

            Assert.Null(result.Error);
            Assert.False(result.Changed);
            Assert.Equal(2, result.Skipped.Count);
            Assert.False(File.Exists(Path.Combine(_local, "reservedports.ini")));
            Assert.False(File.Exists(Path.Combine(_local, "prohibitports.ini")));
            Assert.Empty(Directory.GetFiles(_local, "*.tmp"));
        }

        [Fact]
        public async Task NotDue_SkipsNetwork_AndFailure_StillRecordsLastCheck()
        {
            var handler = new FakeHandler(); // 매니페스트 없음 → 404
            var updater = new ReferenceDataUpdater("https://example.test/data/", new HttpClient(handler), _local);

            ReferenceUpdateResult failed = await updater.CheckAndUpdateAsync(force: false, TimeSpan.FromHours(24));
            Assert.True(failed.Checked);
            Assert.NotNull(failed.Error);
            Assert.NotNull(updater.LastCheck);

            int before = handler.Requests;
            ReferenceUpdateResult skipped = await updater.CheckAndUpdateAsync(force: false, TimeSpan.FromHours(24));
            Assert.False(skipped.Checked);
            Assert.Equal(before, handler.Requests);
        }

        [Fact]
        public void BundledNewerThanLocalCopy_WinsAfterAppUpdate()
        {
            byte[] local = PortsFile(1200, "-local");
            Directory.CreateDirectory(_local);
            File.WriteAllBytes(Path.Combine(_local, "reservedports.ini"), local);
            File.WriteAllText(Path.Combine(_local, "refdata.json"), Manifest(("reservedports.ini", "2026-05-01", local)));
            WriteBundled("reservedports.ini", PortsFile(1200));
            WriteBundled("refdata.json", Encoding.UTF8.GetBytes(Manifest(("reservedports.ini", "2026-09-01", PortsFile(1200)))));

            Assert.Null(ReferenceDataUpdater.PreferredLocalPath("reservedports.ini", _local));
            var versions = ReferenceDataUpdater.EffectiveVersions(_local);
            Assert.Contains(versions, f => f.Name == "reservedports.ini" && f.Version == "2026-09-01");
            Assert.Contains("2026-09-01", ReferenceDataUpdater.Describe(_local));
        }

        [Fact]
        public void Manifest_RoundTrip_DropsUnsafeNames()
        {
            string json = "{\"generated\":\"2026-10-13\",\"files\":[{\"name\":\"../evil\",\"version\":\"1\",\"sha256\":\"x\",\"size\":1},{\"name\":\"vulnrules.json\",\"version\":\"2026-10-13\",\"sha256\":\"abc\",\"size\":3}]}";
            ReferenceManifest? m = ReferenceManifest.Parse(json);
            Assert.NotNull(m);
            Assert.Single(m!.Files);
            Assert.Equal("vulnrules.json", m.Files[0].Name);
            ReferenceManifest? again = ReferenceManifest.Parse(m.ToJson());
            Assert.Equal("abc", again!.Find("VULNRULES.JSON")!.Sha256);
            Assert.Null(ReferenceManifest.Parse("not json"));
        }

        [Fact]
        public void Validate_ChecksEachFormat()
        {
            string ports = Path.Combine(_root, "p.ini"); File.WriteAllBytes(ports, PortsFile(1500));
            string few = Path.Combine(_root, "few.ini"); File.WriteAllBytes(few, PortsFile(5));
            string rules = Path.Combine(_root, "v.json"); File.WriteAllText(rules, Vulnerability.VulnRulesDefault.Json);
            Assert.True(ReferenceDataUpdater.Validate("reservedports.ini", ports));
            Assert.False(ReferenceDataUpdater.Validate("reservedports.ini", few));
            Assert.True(ReferenceDataUpdater.Validate("vulnrules.json", rules));
            Assert.False(ReferenceDataUpdater.Validate("vulnrules.json", ports));
            Assert.False(ReferenceDataUpdater.Validate("unknown.bin", ports));
        }
    }
}
