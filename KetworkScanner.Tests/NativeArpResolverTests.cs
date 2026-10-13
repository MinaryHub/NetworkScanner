using System.Diagnostics;
using System.Text.RegularExpressions;
using KetworkScanner.Platform;

// 여기서 호출하는 internal 파싱 메서드는 OS 의존성이 없는 순수 함수이므로
// 클래스의 [SupportedOSPlatform] 에 따른 플랫폼 호환성 경고(CA1416)를 끈다.
#pragma warning disable CA1416

namespace KetworkScanner.Tests
{
    public class NativeArpResolverTests
    {
        // ---------- Linux: /proc/net/arp ----------

        private const string ProcArpSample =
            "IP address       HW type     Flags       HW address            Mask     Device\n" +
            "192.168.0.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n" +
            "192.168.0.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n" +
            "192.168.0.3      0x1         0x2         00:00:00:00:00:00     *        eth0\n" +
            "192.168.0.4      0x1         0x6         0a:0b:0c:0d:0e:0f     *        eth0\n";

        [Fact]
        public void Linux_CompleteEntry_ReturnsUpperCaseHyphenMac()
        {
            Assert.Equal("00-11-22-33-44-55", LinuxProcArpResolver.FindMac(ProcArpSample, "192.168.0.1"));
        }

        [Fact]
        public void Linux_IncompleteFlag_ReturnsNull()
        {
            Assert.Null(LinuxProcArpResolver.FindMac(ProcArpSample, "192.168.0.2"));
        }

        [Fact]
        public void Linux_ZeroMac_ReturnsNull()
        {
            Assert.Null(LinuxProcArpResolver.FindMac(ProcArpSample, "192.168.0.3"));
        }

        [Fact]
        public void Linux_CompleteWithExtraFlagBits_ReturnsMac()
        {
            Assert.Equal("0A-0B-0C-0D-0E-0F", LinuxProcArpResolver.FindMac(ProcArpSample, "192.168.0.4"));
        }

        [Fact]
        public void Linux_UnknownIpOrEmptyText_ReturnsNull()
        {
            Assert.Null(LinuxProcArpResolver.FindMac(ProcArpSample, "10.0.0.1"));
            Assert.Null(LinuxProcArpResolver.FindMac("", "192.168.0.1"));
        }

        // ---------- macOS: 라우팅 소켓 버퍼 ----------

        // rt_msghdr(92) + sockaddr_inarp(16) + sockaddr_dl(20, 4의 배수로 올림) 형식의 레코드를 만든다.
        private static byte[] BuildMacRecord(byte[] ip, byte[]? mac, byte sdlNlen = 3)
        {
            const int hdr = 92;
            int sdlLen = 8 + sdlNlen + (mac?.Length ?? 0);
            if (sdlLen < 20) sdlLen = 20;
            int sdlStride = (sdlLen + 3) & ~3;
            int msgLen = hdr + 16 + sdlStride;

            byte[] rec = new byte[msgLen];
            BitConverter.GetBytes((ushort)msgLen).CopyTo(rec, 0);
            rec[2] = 5; // rtm_version
            rec[3] = 4; // RTM_GET
            BitConverter.GetBytes(0x400).CopyTo(rec, 8);       // rtm_flags = RTF_LLINFO
            BitConverter.GetBytes(0x1 | 0x2).CopyTo(rec, 12);  // rtm_addrs = RTA_DST | RTA_GATEWAY

            // RTA_DST: sockaddr_inarp
            int p = hdr;
            rec[p] = 16;          // sin_len
            rec[p + 1] = 2;       // AF_INET
            ip.CopyTo(rec, p + 4);
            p += 16;

            // RTA_GATEWAY: sockaddr_dl
            rec[p] = (byte)sdlLen; // sdl_len
            rec[p + 1] = 18;       // AF_LINK
            rec[p + 5] = sdlNlen;
            rec[p + 6] = (byte)(mac?.Length ?? 0);
            for (int i = 0; i < sdlNlen; i++) rec[p + 8 + i] = (byte)('e' + i);
            mac?.CopyTo(rec, p + 8 + sdlNlen);

            return rec;
        }

        [Fact]
        public void MacOS_SampleBuffer_FindsMatchingEntry()
        {
            byte[] r1 = BuildMacRecord(new byte[] { 192, 168, 75, 1 }, new byte[] { 0x00, 0x23, 0xAA, 0x3A, 0x82, 0xBA });
            byte[] r2 = BuildMacRecord(new byte[] { 192, 168, 75, 5 }, new byte[] { 0x42, 0x65, 0xA2, 0x35, 0xA3, 0x67 }, sdlNlen: 4);
            byte[] buf = r1.Concat(r2).ToArray();

            Assert.Equal("00-23-AA-3A-82-BA", MacOSSysctlArpResolver.FindMac(buf, new byte[] { 192, 168, 75, 1 }));
            Assert.Equal("42-65-A2-35-A3-67", MacOSSysctlArpResolver.FindMac(buf, new byte[] { 192, 168, 75, 5 }));
            Assert.Null(MacOSSysctlArpResolver.FindMac(buf, new byte[] { 192, 168, 75, 9 }));
        }

        [Fact]
        public void MacOS_IncompleteEntry_ReturnsNull()
        {
            // sdl_alen == 0 → incomplete
            byte[] r = BuildMacRecord(new byte[] { 169, 254, 169, 254 }, mac: null);
            Assert.Null(MacOSSysctlArpResolver.FindMac(r, new byte[] { 169, 254, 169, 254 }));
        }

        [Fact]
        public void MacOS_ZeroMac_ReturnsNull()
        {
            byte[] r = BuildMacRecord(new byte[] { 10, 0, 0, 1 }, new byte[6]);
            Assert.Null(MacOSSysctlArpResolver.FindMac(r, new byte[] { 10, 0, 0, 1 }));
        }

        [Fact]
        public void MacOS_TruncatedOrEmptyBuffer_ReturnsNull()
        {
            byte[] r = BuildMacRecord(new byte[] { 10, 0, 0, 1 }, new byte[] { 1, 2, 3, 4, 5, 6 });
            Assert.Null(MacOSSysctlArpResolver.FindMac(r.AsSpan(0, 50), new byte[] { 10, 0, 0, 1 }));
            Assert.Null(MacOSSysctlArpResolver.FindMac(ReadOnlySpan<byte>.Empty, new byte[] { 10, 0, 0, 1 }));
        }

        [Fact]
        public void MacOS_ArpCommandOutput_IsNormalised()
        {
            const string output =
                "? (169.254.169.254) at (incomplete) on en0 [ethernet]\n" +
                "? (192.168.75.1) at 0:23:aa:3a:82:ba on en0 ifscope [ethernet]\n" +
                "? (192.168.75.35) at c2:b5:2:50:61:81 on en0 ifscope [ethernet]\n";

            Assert.Equal("00-23-AA-3A-82-BA", MacOSSysctlArpResolver.ParseArpCommandOutput(output, "192.168.75.1"));
            Assert.Equal("C2-B5-02-50-61-81", MacOSSysctlArpResolver.ParseArpCommandOutput(output, "192.168.75.35"));
            Assert.Null(MacOSSysctlArpResolver.ParseArpCommandOutput(output, "169.254.169.254"));
            Assert.Null(MacOSSysctlArpResolver.ParseArpCommandOutput(output, "192.168.75.2"));
        }

        // 실제 macOS 커널의 sysctl 결과와 `arp -an` 의 기본 게이트웨이 MAC이 일치하는지 실측 비교.
        [Fact]
        public void MacOS_Empirical_GatewayMatchesArpCommand()
        {
            if (!OperatingSystem.IsMacOS()) return;

            string routeOut = Run("route", "-n get default");
            Match gw = Regex.Match(routeOut, @"gateway:\s*([\d.]+)");
            if (!gw.Success) return; // 네트워크 없음 — 검증 불가

            string gateway = gw.Groups[1].Value;
            string arpOut = Run("arp", "-an");
            string? expected = MacOSSysctlArpResolver.ParseArpCommandOutput(arpOut, gateway);
            if (expected == null)
            {
                Run("ping", $"-c1 -W1000 {gateway}");
                arpOut = Run("arp", "-an");
                expected = MacOSSysctlArpResolver.ParseArpCommandOutput(arpOut, gateway);
            }
            if (expected == null) return; // ARP 캐시를 채우지 못함 — 검증 불가

            string? actual = new MacOSSysctlArpResolver().Resolve(gateway);
            Assert.Equal(expected, actual);
        }

        // ---------- Windows: MIB_IPNET_ROW2 ----------

        private static byte[] BuildWindowsRow(byte[] ip, byte[] mac, int state, uint physLen = 6, ushort family = 2)
        {
            byte[] row = new byte[88];
            BitConverter.GetBytes(family).CopyTo(row, 0);
            ip.CopyTo(row, 4);
            BitConverter.GetBytes(3u).CopyTo(row, 28);        // InterfaceIndex
            BitConverter.GetBytes(0x123456789UL).CopyTo(row, 32); // NET_LUID
            mac.CopyTo(row, 40);
            BitConverter.GetBytes(physLen).CopyTo(row, 72);
            BitConverter.GetBytes(state).CopyTo(row, 76);
            BitConverter.GetBytes(30000u).CopyTo(row, 84);    // ReachabilityTime
            return row;
        }

        [Theory]
        [InlineData(2)] // Reachable
        [InlineData(3)] // Stale
        [InlineData(4)] // Delay
        [InlineData(5)] // Probe
        [InlineData(6)] // Permanent
        public void Windows_ValidStates_ReturnMac(int state)
        {
            byte[] row = BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, state);
            Assert.Equal("DE-AD-BE-EF-00-01", WindowsIpNetTableArpResolver.ParseRow(row, new byte[] { 10, 0, 0, 1 }));
        }

        [Theory]
        [InlineData(0)] // Unreachable
        [InlineData(1)] // Incomplete
        public void Windows_InvalidStates_ReturnNull(int state)
        {
            byte[] row = BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, state);
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(row, new byte[] { 10, 0, 0, 1 }));
        }

        [Fact]
        public void Windows_WrongIpOrLengthOrFamilyOrZeroMac_ReturnNull()
        {
            byte[] mac = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, mac, 2), new byte[] { 10, 0, 0, 2 }));
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, mac, 2, physLen: 0), new byte[] { 10, 0, 0, 1 }));
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, mac, 2, family: 23), new byte[] { 10, 0, 0, 1 }));
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(BuildWindowsRow(new byte[] { 10, 0, 0, 1 }, new byte[6], 2), new byte[] { 10, 0, 0, 1 }));
            Assert.Null(WindowsIpNetTableArpResolver.ParseRow(new byte[40], new byte[] { 10, 0, 0, 1 }));
        }

        // ---------- Factory ----------

        [Fact]
        public void Factory_ReturnsResolverForCurrentOS_AndNeverThrows()
        {
            IArpResolver resolver = ArpResolverFactory.CreateForCurrentOS();
            Assert.NotNull(resolver);
            // 잘못된 입력에도 예외 없이 null
            Assert.Null(resolver.Resolve("not-an-ip"));
            Assert.Null(resolver.Resolve(""));
        }

        private static string Run(string file, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                };
                using Process? p = Process.Start(psi);
                if (p == null) return "";
                string o = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);
                return o;
            }
            catch
            {
                return "";
            }
        }
    }
}
