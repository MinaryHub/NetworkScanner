using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace KetworkScanner.Upload
{
    // SFTP 업로드(SSH.NET). 호스트키는 설정의 지문과 비교하고, 지문이 비어 있으면 최초 접속 시 known_hosts에
    // 저장(TOFU)한 뒤 이후 접속부터는 저장된 키와 일치해야 한다 — 중간자 공격으로 바뀐 키를 거부하기 위함.
    public sealed class SftpUploader : IResultUploader
    {
        public UploadProtocol Protocol => UploadProtocol.Sftp;

        public static string KnownHostsPath => UserDataPaths.Resolve("known_hosts");

        public Task UploadAsync(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct)
            => Task.Run(() => Upload(localPath, remoteFileName, settings, ct), ct);

        private static void Upload(string localPath, string remoteFileName, UploadSettings settings, CancellationToken ct)
        {
            string hostKeyId = $"{settings.Host}:{settings.EffectivePort}";
            var auth = new PasswordAuthenticationMethod(settings.User, settings.Password);
            var info = new ConnectionInfo(settings.Host, settings.EffectivePort, settings.User, auth)
            {
                Timeout = TimeSpan.FromSeconds(15),
            };

            using var client = new SftpClient(info);
            client.OperationTimeout = TimeSpan.FromSeconds(60);

            string? rejection = null;
            client.HostKeyReceived += (_, e) =>
            {
                string actual = Fingerprint.Sha256Hex(e.HostKey);
                if (!string.IsNullOrWhiteSpace(settings.ServerFingerprint))
                {
                    e.CanTrust = Fingerprint.Matches(settings.ServerFingerprint, actual);
                    if (!e.CanTrust) rejection = $"host key fingerprint mismatch (got {actual})";
                    return;
                }

                string? known = KnownHosts.Lookup(hostKeyId);
                if (known == null)
                {
                    KnownHosts.Remember(hostKeyId, actual);
                    e.CanTrust = true;
                }
                else
                {
                    e.CanTrust = Fingerprint.Matches(known, actual);
                    if (!e.CanTrust) rejection = $"host key changed for {hostKeyId} (known {known}, got {actual})";
                }
            };

            try
            {
                client.Connect();
                ct.ThrowIfCancellationRequested();

                string remoteDir = string.IsNullOrWhiteSpace(settings.RemoteDirectory) ? "." : settings.RemoteDirectory.TrimEnd('/');
                EnsureDirectory(client, remoteDir);

                using FileStream fs = File.OpenRead(localPath);
                client.UploadFile(fs, remoteDir + "/" + remoteFileName, canOverride: true);
            }
            catch (SshAuthenticationException ex)
            {
                throw new UploadException(ex.Message, permanent: true, inner: ex);
            }
            catch (SshConnectionException ex)
            {
                throw new UploadException(rejection ?? ex.Message, permanent: rejection != null, inner: ex);
            }
            catch (Exception ex) when (ex is SshException || ex is IOException || ex is System.Net.Sockets.SocketException)
            {
                throw new UploadException(rejection ?? ex.Message, permanent: rejection != null, inner: ex);
            }
        }

        private static void EnsureDirectory(SftpClient client, string path)
        {
            if (path == "." || path == "/" || path.Length == 0) return;
            string current = path.StartsWith('/') ? "/" : "";
            foreach (string part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                current = current.Length == 0 || current.EndsWith('/') ? current + part : current + "/" + part;
                if (!client.Exists(current)) client.CreateDirectory(current);
            }
        }

        // "host:port<TAB>SHA256-hex" 한 줄씩 보관하는 간단한 known_hosts.
        internal static class KnownHosts
        {
            private static readonly object Lock = new();

            public static string? Lookup(string id)
            {
                lock (Lock)
                {
                    foreach (var (k, v) in ReadAll())
                        if (string.Equals(k, id, StringComparison.OrdinalIgnoreCase)) return v;
                    return null;
                }
            }

            public static void Remember(string id, string fingerprintHex)
            {
                lock (Lock)
                {
                    var all = ReadAll();
                    all.RemoveAll(p => string.Equals(p.Item1, id, StringComparison.OrdinalIgnoreCase));
                    all.Add((id, fingerprintHex));
                    var sb = new StringBuilder();
                    foreach (var (k, v) in all) sb.Append(k).Append('\t').Append(v).Append('\n');
                    try { File.WriteAllText(KnownHostsPath, sb.ToString(), Encoding.UTF8); } catch { }
                }
            }

            private static List<(string, string)> ReadAll()
            {
                var list = new List<(string, string)>();
                try
                {
                    if (!File.Exists(KnownHostsPath)) return list;
                    foreach (string line in File.ReadAllLines(KnownHostsPath, Encoding.UTF8))
                    {
                        string[] t = line.Split('\t');
                        if (t.Length == 2) list.Add((t[0], t[1]));
                    }
                }
                catch { }
                return list;
            }
        }
    }
}
