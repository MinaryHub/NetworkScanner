using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Fingerprint
{
    // SSH(22) 핑거프린트: 서버가 먼저 보내는 식별 문자열 한 줄만 읽고 끊는다. 키 교환은 하지 않는다.
    public sealed class SshProbe : IFactProbe
    {
        public const int DefaultPort = 22;
        public const string Source = SshBannerParser.Source;
        private const int MaxLineBytes = 255;
        private const int MaxPreambleLines = 8;   // RFC 4253: 식별 문자열 앞에 다른 줄이 올 수 있다

        private readonly int _port;

        public SshProbe() : this(DefaultPort) { }

        internal SshProbe(int port) => _port = port;

        public string Name => Source;

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            if (openPorts == null || !openPorts.Contains(_port)) return ProbeTcp.Empty;
            try
            {
                using CancellationTokenSource cts = ProbeTcp.Linked(ct, timeoutMs);
                string? banner = await ReadBannerAsync(ip, _port, cts.Token).ConfigureAwait(false);
                return banner == null ? ProbeTcp.Empty : SshBannerParser.Facts(banner);
            }
            catch
            {
                return ProbeTcp.Empty;
            }
        }

        // "SSH-"로 시작하는 첫 줄(최대 255바이트)을 돌려준다. 없으면 null.
        internal static async Task<string?> ReadBannerAsync(string ip, int port, CancellationToken ct)
        {
            using TcpClient? client = await ProbeTcp.ConnectAsync(ip, port, ct).ConfigureAwait(false);
            if (client == null) return null;
            NetworkStream stream = client.GetStream();

            var line = new byte[MaxLineBytes];
            var one = new byte[1];
            for (int lines = 0; lines < MaxPreambleLines; lines++)
            {
                int len = 0;
                bool eol = false;
                while (len < MaxLineBytes)
                {
                    int n = await stream.ReadAsync(one.AsMemory(0, 1), ct).ConfigureAwait(false);
                    if (n <= 0) return Decode(line, len);
                    if (one[0] == (byte)'\n') { eol = true; break; }
                    line[len++] = one[0];
                }
                string? text = Decode(line, len);
                if (text != null && text.StartsWith("SSH-", StringComparison.Ordinal)) return text;
                if (!eol) return null;   // 255바이트가 넘도록 줄바꿈이 없으면 SSH가 아니다
            }
            return null;
        }

        private static string? Decode(byte[] buf, int len)
        {
            if (len <= 0) return null;
            string s = Encoding.ASCII.GetString(buf, 0, len).TrimEnd('\r').Trim();
            return s.Length == 0 ? null : s;
        }
    }
}
