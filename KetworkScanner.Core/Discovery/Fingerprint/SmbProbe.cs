using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Discovery.Fingerprint
{
    // SMB(445) 핑거프린트: SMB2 NEGOTIATE → NTLMSSP SESSION_SETUP까지 보내고, 서버가 CHALLENGE에 실어 보내는
    // OS 버전·컴퓨터 이름·도메인을 읽는다. 자격 증명은 보내지 않는다(세션은 인증 전 단계에서 끊는다).
    // SMB2를 모르는 서버에는 SMB1 NEGOTIATE("NT LM 0.12")로 다시 한 번 물어 구형 장비를 표시한다.
    public sealed class SmbProbe : IFactProbe
    {
        public const int DefaultPort = 445;
        public const string Source = "SMB";

        private readonly int _port;

        public SmbProbe() : this(DefaultPort) { }

        internal SmbProbe(int port) => _port = port;

        public string Name => Source;

        public async Task<IReadOnlyList<Fact>> ProbeAsync(string ip, IReadOnlyList<int> openPorts, int timeoutMs, CancellationToken ct)
        {
            if (openPorts == null || !openPorts.Contains(_port)) return ProbeTcp.Empty;
            try
            {
                using CancellationTokenSource cts = ProbeTcp.Linked(ct, timeoutMs);
                var result = await ProbeSmb2Async(ip, cts.Token).ConfigureAwait(false);
                if (result.Smb2Answered) return result.Facts;

                // SMB2 헤더가 돌아오지 않았다 → SMB1 전용 서버인지 확인(새 연결).
                using CancellationTokenSource cts1 = ProbeTcp.Linked(ct, timeoutMs);
                return await ProbeSmb1Async(ip, cts1.Token).ConfigureAwait(false);
            }
            catch
            {
                return ProbeTcp.Empty;
            }
        }

        private async Task<(bool Smb2Answered, IReadOnlyList<Fact> Facts)> ProbeSmb2Async(string ip, CancellationToken ct)
        {
            using TcpClient? client = await ProbeTcp.ConnectAsync(ip, _port, ct).ConfigureAwait(false);
            if (client == null) return (false, ProbeTcp.Empty);
            NetworkStream stream = client.GetStream();

            byte[] negotiate = Smb2Codec.BuildNegotiateRequest(Guid.NewGuid());
            await stream.WriteAsync(negotiate, ct).ConfigureAwait(false);
            byte[]? reply = await Smb2Codec.ReadFrameAsync(stream, ct).ConfigureAwait(false);
            if (reply == null || !Smb2Codec.TryParseNegotiateResponse(reply, out ushort dialect)) return (false, ProbeTcp.Empty);

            byte[] blob = SpnegoCodec.WrapNegTokenInit(NtlmCodec.BuildNegotiateMessage());
            await stream.WriteAsync(Smb2Codec.BuildSessionSetupRequest(blob), ct).ConfigureAwait(false);
            byte[]? setup = await Smb2Codec.ReadFrameAsync(stream, ct).ConfigureAwait(false);

            NtlmCodec.Challenge? challenge = null;
            if (setup != null && Smb2Codec.TryParseSessionSetupResponse(setup, out _, out byte[] security))
            {
                byte[]? token = SpnegoCodec.ExtractNtlmToken(security);
                if (token != null && NtlmCodec.TryParseChallenge(token, out var c)) challenge = c;
            }
            return (true, FactsFrom(dialect, challenge));
        }

        private async Task<IReadOnlyList<Fact>> ProbeSmb1Async(string ip, CancellationToken ct)
        {
            using TcpClient? client = await ProbeTcp.ConnectAsync(ip, _port, ct).ConfigureAwait(false);
            if (client == null) return ProbeTcp.Empty;
            NetworkStream stream = client.GetStream();
            await stream.WriteAsync(Smb2Codec.BuildSmb1NegotiateRequest(), ct).ConfigureAwait(false);
            byte[]? reply = await Smb2Codec.ReadFrameAsync(stream, ct).ConfigureAwait(false);
            if (reply == null || !Smb2Codec.TryParseSmb1NegotiateResponse(reply, out _)) return ProbeTcp.Empty;

            var facts = new FactList(Source);
            facts.Add(FactFields.Os, "Windows (legacy SMB1)", Confidence.Low);
            facts.Add(FactFields.Service, "SMB1", Confidence.Medium);
            return facts.ToList();
        }

        // 협상된 다이얼렉트 + NTLM CHALLENGE → Fact. challenge가 null이면 SMB2 서버라는 사실만 남긴다.
        internal static IReadOnlyList<Fact> FactsFrom(ushort dialect, NtlmCodec.Challenge? challenge)
        {
            var facts = new FactList(Source);
            facts.Add(FactFields.Service, Smb2Codec.DialectName(dialect), Confidence.Medium);

            if (challenge == null)
            {
                facts.Add(FactFields.Os, "Windows/SMB server", Confidence.Low);
                return facts.ToList();
            }

            NtlmCodec.Version? v = challenge.Version;
            if (v == null)
            {
                facts.Add(FactFields.Os, "Windows/SMB server", Confidence.Low);
            }
            else if (v.Value.Major == 6 && v.Value.Minor == 1 && v.Value.Build == 0)
            {
                // Samba는 6.1.0을 고정으로 보낸다. 진짜 Windows 7은 항상 7600/7601 빌드를 보낸다.
                facts.Add(FactFields.Os, "Linux (Samba)", Confidence.Medium);
            }
            else
            {
                facts.Add(FactFields.Os, "Windows", Confidence.High);
                facts.Add(FactFields.OsVersion, NtlmCodec.WindowsVersionName(v.Value.Major, v.Value.Minor, v.Value.Build), Confidence.High);
            }

            if (challenge.NbComputerName != null) facts.Add(FactFields.Name, challenge.NbComputerName, Confidence.High);
            else if (challenge.DnsComputerName != null) facts.Add(FactFields.Name, challenge.DnsComputerName, Confidence.Medium);
            else if (challenge.TargetName != null) facts.Add(FactFields.Name, challenge.TargetName, Confidence.Low);

            if (challenge.NbDomainName != null) facts.Add(FactFields.Domain, challenge.NbDomainName, Confidence.High);
            else if (challenge.DnsDomainName != null) facts.Add(FactFields.Domain, challenge.DnsDomainName, Confidence.Medium);

            return facts.ToList();
        }
    }
}
