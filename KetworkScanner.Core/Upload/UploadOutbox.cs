using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Upload
{
    // 업로드 실패분을 보관했다가 재전송하는 대기열. 결과 파일은 복사해 두고(원본은 env/에 그대로 남김)
    // 옆에 .json 메타(시도 횟수, 마지막 오류, 다음 시도 시각)를 둔다. 서버가 잠시 내려가도 결과가 유실되지 않는다.
    public sealed class UploadOutbox
    {
        public const string FolderName = "outbox";
        public static readonly TimeSpan[] Backoff =
        {
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15),
            TimeSpan.FromHours(1), TimeSpan.FromHours(6), TimeSpan.FromHours(24),
        };
        public int MaxAttempts { get; set; } = 30;

        public sealed class Entry
        {
            public string FileName { get; set; } = "";
            public string RemoteName { get; set; } = "";
            public int Attempts { get; set; }
            public string LastError { get; set; } = "";
            public DateTimeOffset CreatedAt { get; set; }
            public DateTimeOffset NextAttemptAt { get; set; }
        }

        private readonly string _dir;
        private readonly SemaphoreSlim _flushLock = new(1, 1);

        public UploadOutbox(string? directory = null)
        {
            _dir = directory ?? UserDataPaths.Resolve(FolderName);
        }

        public string Directory => _dir;

        public void Enqueue(string localPath, string remoteName, string error)
        {
            System.IO.Directory.CreateDirectory(_dir);
            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", CultureInfo.InvariantCulture);
            string fileName = stamp + "_" + Path.GetFileName(localPath);
            File.Copy(localPath, Path.Combine(_dir, fileName), overwrite: true);
            var entry = new Entry
            {
                FileName = fileName,
                RemoteName = remoteName,
                Attempts = 1,
                LastError = error,
                CreatedAt = DateTimeOffset.UtcNow,
                NextAttemptAt = DateTimeOffset.UtcNow + Backoff[0],
            };
            WriteMeta(entry);
        }

        public IReadOnlyList<Entry> List()
        {
            var list = new List<Entry>();
            if (!System.IO.Directory.Exists(_dir)) return list;
            foreach (string meta in System.IO.Directory.EnumerateFiles(_dir, "*.json"))
            {
                try
                {
                    Entry? e = JsonSerializer.Deserialize<Entry>(File.ReadAllText(meta));
                    if (e != null && File.Exists(Path.Combine(_dir, e.FileName))) list.Add(e);
                }
                catch { }
            }
            list.Sort((a, b) => a.CreatedAt.CompareTo(b.CreatedAt));
            return list;
        }

        public int Count => List().Count;

        // 기한이 된 항목을 순서대로 재전송한다. 성공한 개수를 돌려준다.
        public async Task<int> FlushAsync(IResultUploader uploader, UploadSettings settings, Action<string>? log, CancellationToken ct)
        {
            if (!await _flushLock.WaitAsync(0, ct).ConfigureAwait(false)) return 0; // 이미 다른 플러시가 진행 중
            try
            {
                int sent = 0;
                foreach (Entry e in List())
                {
                    ct.ThrowIfCancellationRequested();
                    if (e.NextAttemptAt > DateTimeOffset.UtcNow) continue;

                    string local = Path.Combine(_dir, e.FileName);
                    try
                    {
                        await uploader.UploadAsync(local, e.RemoteName, settings, ct).ConfigureAwait(false);
                        Remove(e);
                        sent++;
                        log?.Invoke(string.Format(Localization.T("msg.upload.done"), e.RemoteName));
                    }
                    catch (UploadException ex)
                    {
                        e.Attempts++;
                        e.LastError = ex.Message;
                        if (e.Attempts >= MaxAttempts)
                        {
                            log?.Invoke($"outbox: giving up on {e.RemoteName} after {e.Attempts} attempts: {ex.Message}");
                            MoveToFailed(e);
                            continue;
                        }
                        e.NextAttemptAt = DateTimeOffset.UtcNow + Backoff[Math.Min(e.Attempts - 1, Backoff.Length - 1)];
                        WriteMeta(e);
                        log?.Invoke(string.Format(Localization.T("msg.upload.failed"), e.RemoteName, ex.Message));
                        if (ex.IsPermanent) break; // 인증 실패 등은 다른 항목도 똑같이 실패하므로 이번 회차는 중단
                    }
                }
                return sent;
            }
            finally
            {
                _flushLock.Release();
            }
        }

        private void Remove(Entry e)
        {
            try { File.Delete(Path.Combine(_dir, e.FileName)); } catch { }
            try { File.Delete(MetaPath(e)); } catch { }
        }

        private void MoveToFailed(Entry e)
        {
            string failed = Path.Combine(_dir, "failed");
            System.IO.Directory.CreateDirectory(failed);
            try { File.Move(Path.Combine(_dir, e.FileName), Path.Combine(failed, e.FileName), overwrite: true); } catch { }
            try { File.Delete(MetaPath(e)); } catch { }
        }

        private string MetaPath(Entry e) => Path.Combine(_dir, e.FileName + ".json");

        private void WriteMeta(Entry e)
        {
            File.WriteAllText(MetaPath(e), JsonSerializer.Serialize(e, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    // 엔진이 쓰는 업로드 창구: 즉시 전송을 시도하고 실패하면 outbox에 넣는다. 전송 전에 밀린 항목도 함께 보낸다.
    public sealed class UploadService
    {
        private readonly UploadOutbox _outbox;
        private readonly Func<UploadProtocol, IResultUploader> _factory;

        public UploadService(UploadOutbox? outbox = null, Func<UploadProtocol, IResultUploader>? factory = null)
        {
            _outbox = outbox ?? new UploadOutbox();
            _factory = factory ?? UploaderFactory.Create;
        }

        public UploadOutbox Outbox => _outbox;

        public async Task<bool> UploadAsync(string localPath, UploadSettings settings, Action<string>? log, CancellationToken ct)
        {
            if (!settings.Enabled) return false;
            IResultUploader uploader = _factory(settings.Protocol);
            string remoteName = Path.GetFileName(localPath);

            try
            {
                await uploader.UploadAsync(localPath, remoteName, settings, ct).ConfigureAwait(false);
                log?.Invoke(string.Format(Localization.T("msg.upload.done"), remoteName));
            }
            catch (UploadException ex)
            {
                _outbox.Enqueue(localPath, remoteName, ex.Message);
                log?.Invoke(string.Format(Localization.T("msg.upload.queued"), remoteName + " - " + ex.Message));
                return false;
            }

            try { await _outbox.FlushAsync(uploader, settings, log, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            return true;
        }

        public Task<int> FlushAsync(UploadSettings settings, Action<string>? log, CancellationToken ct)
            => settings.Enabled ? _outbox.FlushAsync(_factory(settings.Protocol), settings, log, ct) : Task.FromResult(0);
    }
}
