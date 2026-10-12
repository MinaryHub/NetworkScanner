using System;
using System.Collections.Generic;
using System.Linq;
using NetworkScanner.Discovery;
using NetworkScanner.Discovery.Fingerprint;

namespace NetworkScanner.Tests
{
    public class FingerprintProbeTests
    {
        private static string? Best(IReadOnlyList<Fact> facts, string field)
            => facts.Where(f => f.Field == field).OrderByDescending(f => (int)f.Confidence).FirstOrDefault()?.Value;

        [Theory]
        [InlineData("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "Ubuntu")]
        [InlineData("SSH-2.0-dropbear_2022.83", "Embedded")]
        [InlineData("SSH-2.0-ROSSSH", "MikroTik")]
        [InlineData("SSH-2.0-OpenSSH_for_Windows_9.5", "Windows")]
        public void SshBanner_ProducesOsFacts(string banner, string expectedOsFragment)
        {
            IReadOnlyList<Fact> facts = SshBannerParser.Facts(banner);
            string os = (Best(facts, FactFields.Os) ?? "") + " " + (Best(facts, FactFields.OsVersion) ?? "");
            Assert.Contains(expectedOsFragment, os, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(Best(facts, FactFields.Service));
        }

        [Fact]
        public void SshBanner_GarbageYieldsNothing()
        {
            Assert.Empty(SshBannerParser.Facts("HTTP/1.1 400 Bad Request"));
            Assert.Empty(SshBannerParser.Facts(null));
        }

        [Fact]
        public void HttpFingerprints_MatchRouterAndWindows()
        {
            IReadOnlyList<Fact> mikrotik = HttpFingerprints.Match(null, "RouterOS router configuration page", "");
            Assert.Contains("MikroTik", Best(mikrotik, FactFields.Vendor) ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.Equal("router", Best(mikrotik, FactFields.DeviceType));

            IReadOnlyList<Fact> win = HttpFingerprints.Match("Microsoft-HTTPAPI/2.0", null, null);
            Assert.Equal("Windows", Best(win, FactFields.Os));

            IReadOnlyList<Fact> syno = HttpFingerprints.Match(null, "Synology DiskStation", "");
            Assert.Contains("Synology", Best(syno, FactFields.Vendor) ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.Equal("nas", Best(syno, FactFields.DeviceType));
        }

        [Fact]
        public void NtlmChallenge_RoundTrip_ExposesWindowsVersionAndNames()
        {
            byte[] msg = NtlmCodec.BuildChallengeMessage("WORKGROUP", new NtlmCodec.Version(10, 0, 19045), new[]
            {
                new KeyValuePair<ushort, string>(1, "PC7"),         // MsvAvNbComputerName
                new KeyValuePair<ushort, string>(2, "WORKGROUP"),   // MsvAvNbDomainName
                new KeyValuePair<ushort, string>(3, "pc7.local"),   // MsvAvDnsComputerName
            });

            Assert.True(NtlmCodec.TryParseChallenge(msg, out var challenge));
            Assert.Equal("PC7", challenge.NbComputerName);
            Assert.Equal("WORKGROUP", challenge.NbDomainName);
            Assert.Equal(10, challenge.Version!.Value.Major);
            Assert.Equal(19045, challenge.Version.Value.Build);
            Assert.Contains("Windows 10", NtlmCodec.WindowsVersionName(10, 0, 19045));
            Assert.Contains("Windows 11", NtlmCodec.WindowsVersionName(10, 0, 22631));
            Assert.Contains("Server 2022", NtlmCodec.WindowsVersionName(10, 0, 20348));
        }

        [Fact]
        public void Smb2Negotiate_RequestIsWellFormed()
        {
            byte[] framed = Smb2Codec.BuildNegotiateRequest(Guid.NewGuid());
            byte[] req = framed.AsSpan(4).ToArray(); // NetBIOS 4바이트 프레임 제거
            Assert.True(Smb2Codec.TryParseHeader(req, out var header));
            Assert.Equal(0, header.Command);
            Assert.True(Smb2Codec.TryParseNegotiateRequest(req, out ushort[] dialects));
            Assert.Contains((ushort)0x0311, dialects);
        }
    }
}
