using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using NetworkScanner;
using NetworkScanner.Notifications;
using NetworkScanner.Upload;

namespace NetworkScanner.Tests
{
    public class UploadAndNotifyTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "nstest-upload-" + Guid.NewGuid().ToString("N"));

        public UploadAndNotifyTests() { Directory.CreateDirectory(_root); UserDataPaths.OverrideRoot = _root; }
        public void Dispose() { UserDataPaths.OverrideRoot = null; try { Directory.Delete(_root, true); } catch { } }

        private sealed class FlakyUploader : IResultUploader
        {
            public int FailuresLeft;
            public bool Permanent { get; set; }
            public List<string> Sent { get; } = new();
            public UploadProtocol Protocol => UploadProtocol.Ftps;
            public Task UploadAsync(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct)
            {
                if (FailuresLeft > 0)
                {
                    FailuresLeft--;
                    throw new UploadException("boom", Permanent);
                }
                Sent.Add(remoteFileName);
                return Task.CompletedTask;
            }
        }

        private UploadSettings Settings() => new() { Enabled = true, Host = "h", Protocol = UploadProtocol.Ftps };

        [Fact]
        public async Task FailedUpload_IsQueued_AndRetriedLater()
        {
            string file = Path.Combine(_root, "scan.csv");
            File.WriteAllText(file, "a,b");
            var uploader = new FlakyUploader { FailuresLeft = 1 };
            var outbox = new UploadOutbox(Path.Combine(_root, "outbox"));
            var service = new UploadService(outbox, _ => uploader);

            bool ok = await service.UploadAsync(file, Settings(), null, CancellationToken.None);

            Assert.False(ok);
            Assert.Equal(1, outbox.Count);
            Assert.Empty(uploader.Sent);

            // 백오프 기한 전에는 재시도하지 않는다.
            Assert.Equal(0, await outbox.FlushAsync(uploader, Settings(), null, CancellationToken.None));

            // 기한을 과거로 돌려 재시도되게 한다.
            foreach (var e in outbox.List())
            {
                e.NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-1);
                File.WriteAllText(Path.Combine(outbox.Directory, e.FileName + ".json"), System.Text.Json.JsonSerializer.Serialize(e));
            }
            Assert.Equal(1, await outbox.FlushAsync(uploader, Settings(), null, CancellationToken.None));
            Assert.Equal(0, outbox.Count);
            Assert.Single(uploader.Sent);
        }

        [Fact]
        public async Task SuccessfulUpload_AlsoFlushesPendingItems()
        {
            string a = Path.Combine(_root, "a.csv"); File.WriteAllText(a, "1");
            string b = Path.Combine(_root, "b.csv"); File.WriteAllText(b, "2");
            var outbox = new UploadOutbox(Path.Combine(_root, "outbox"));
            outbox.Enqueue(a, "a.csv", "earlier failure");
            foreach (var e in outbox.List())
            {
                e.NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-1);
                File.WriteAllText(Path.Combine(outbox.Directory, e.FileName + ".json"), System.Text.Json.JsonSerializer.Serialize(e));
            }
            var uploader = new FlakyUploader();
            var service = new UploadService(outbox, _ => uploader);

            Assert.True(await service.UploadAsync(b, Settings(), null, CancellationToken.None));

            Assert.Equal(new[] { "b.csv", "a.csv" }, uploader.Sent);
            Assert.Equal(0, outbox.Count);
        }

        [Fact]
        public async Task Upload_IsSkipped_WhenDisabled()
        {
            var uploader = new FlakyUploader();
            var service = new UploadService(new UploadOutbox(Path.Combine(_root, "outbox")), _ => uploader);
            Assert.False(await service.UploadAsync(Path.Combine(_root, "x"), new UploadSettings { Enabled = false }, null, CancellationToken.None));
            Assert.Empty(uploader.Sent);
        }

        [Fact]
        public async Task PermanentFailure_StopsFlushingRemainingItems()
        {
            string a = Path.Combine(_root, "a.csv"); File.WriteAllText(a, "1");
            string b = Path.Combine(_root, "b.csv"); File.WriteAllText(b, "2");
            var outbox = new UploadOutbox(Path.Combine(_root, "outbox"));
            outbox.Enqueue(a, "a.csv", "x");
            outbox.Enqueue(b, "b.csv", "x");
            foreach (var e in outbox.List())
            {
                e.NextAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-1);
                File.WriteAllText(Path.Combine(outbox.Directory, e.FileName + ".json"), System.Text.Json.JsonSerializer.Serialize(e));
            }
            var uploader = new FlakyUploader { FailuresLeft = 1, Permanent = true };

            int sent = await outbox.FlushAsync(uploader, Settings(), null, CancellationToken.None);

            Assert.Equal(0, sent);
            Assert.Equal(2, outbox.Count);      // 두 번째 항목은 시도조차 하지 않는다(같은 이유로 실패할 것이므로)
            Assert.Equal(2, outbox.List()[0].Attempts);
            Assert.Equal(1, outbox.List()[1].Attempts);
        }

        [Theory]
        [InlineData("ab:cd:EF", "ABCDEF", true)]
        [InlineData("AB-CD-EF", "abcdef", true)]
        [InlineData("ABCDEF", "ABCDE0", false)]
        public void Fingerprint_MatchesIgnoringSeparatorsAndCase(string expected, string actual, bool matches)
        {
            Assert.Equal(matches, Fingerprint.Matches(expected, actual));
        }

        [Fact]
        public void Fingerprint_AcceptsOpenSshBase64Form()
        {
            byte[] data = { 1, 2, 3 };
            string hex = Fingerprint.Sha256Hex(data);
            string b64 = "SHA256:" + Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(data)).TrimEnd('=');
            Assert.True(Fingerprint.Matches(b64, hex));
        }

        private sealed class FakeChannel : INotificationChannel
        {
            public List<string> Bodies { get; } = new();
            public bool Fail;
            public string Name => "fake";
            public Task SendAsync(string subject, string body, CancellationToken ct)
            {
                if (Fail) throw new InvalidOperationException("down");
                Bodies.Add(body);
                return Task.CompletedTask;
            }
        }

        [Fact]
        public async Task Notifier_SendsOnlySecurityChanges_WhenConfigured_AndSurvivesChannelFailure()
        {
            var settings = new NotificationSettings { Enabled = true, OnSecurityOnly = true };
            var good = new FakeChannel();
            var bad = new FakeChannel { Fail = true };
            var notifier = new Notifier(settings, new INotificationChannel[] { bad, good });
            var changes = new List<ScanChange>
            {
                new(ScanChangeType.NewHost, "10.0.0.1", "new"),
                new(ScanChangeType.MacChanged, "10.0.0.2", "A → B"),
            };

            int sent = await notifier.NotifyChangesAsync("sys", changes, CancellationToken.None);

            Assert.Equal(1, sent);
            Assert.Single(good.Bodies);
            Assert.Contains("10.0.0.2", good.Bodies[0]);
            Assert.DoesNotContain("10.0.0.1", good.Bodies[0]);
        }

        [Fact]
        public async Task Notifier_DoesNothing_WhenDisabledOrNoRelevantChanges()
        {
            var ch = new FakeChannel();
            var disabled = new Notifier(new NotificationSettings { Enabled = false }, new[] { ch });
            Assert.Equal(0, await disabled.NotifyChangesAsync("s", new[] { new ScanChange(ScanChangeType.MacChanged, "1", "") }, CancellationToken.None));

            var securityOnly = new Notifier(new NotificationSettings { Enabled = true, OnSecurityOnly = true }, new[] { ch });
            Assert.Equal(0, await securityOnly.NotifyChangesAsync("s", new[] { new ScanChange(ScanChangeType.NewHost, "1", "") }, CancellationToken.None));
            Assert.Empty(ch.Bodies);
        }
    }
}
