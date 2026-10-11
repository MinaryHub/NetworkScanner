using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace NetworkScanner.Platform
{
    // sysctl(NET_RT_FLAGS, RTF_LLINFO) 로 라우팅 소켓의 ARP 테이블을 덤프해 MAC을 조회한다.
    // sysctl 이 실패하면 `arp -an` 출력 파싱으로 폴백한다.
    //
    // 버퍼 레이아웃(macOS arm64/x64 에서 실측 검증, 2026-10):
    //   struct rt_msghdr = 92 바이트 (rtm_msglen@0 u16, rtm_flags@8 i32, rtm_addrs@12 i32, rt_metrics@36 56바이트)
    //   헤더 뒤에 rtm_addrs 비트 순서(RTA_DST=1, RTA_GATEWAY=2, ...)로 sockaddr 가 이어진다.
    //   각 sockaddr 의 sa_len 은 바이트 0; 4의 배수로 올림해 전진하며 sa_len 0 은 4바이트로 취급.
    //   RTA_DST     → sockaddr_inarp(16): sin_addr@4
    //   RTA_GATEWAY → sockaddr_dl(20):    sdl_nlen@5, sdl_alen@6, 링크 주소@8+sdl_nlen
    [SupportedOSPlatform("macos")]
    public sealed class MacOSSysctlArpResolver : IArpResolver
    {
        internal const int RtMsgHdrSize = 92;
        private const int OffRtmMsgLen = 0;
        private const int OffRtmAddrs = 12;
        private const int RtaDst = 0x1;
        private const int RtaGateway = 0x2;
        private const int OffSinAddr = 4;
        private const int OffSdlNlen = 5;
        private const int OffSdlAlen = 6;
        private const int OffSdlData = 8;

        private const int CtlNet = 4;
        private const int PfRoute = 17;
        private const int AfInet = 2;
        private const int NetRtFlags = 2;
        private const int RtfLlInfo = 0x400;

        private static readonly Regex ArpLineRegex = new(@"\(([\d.]+)\) at ([0-9a-f:]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        [DllImport("libc", SetLastError = true)]
        private static extern int sysctl(int[] name, uint namelen, byte[]? oldp, ref nuint oldlenp, IntPtr newp, nuint newlen);

        public string? Resolve(string ipv4)
        {
            try
            {
                if (!IPAddress.TryParse(ipv4, out IPAddress? addr) || addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return null;

                byte[]? table = DumpArpTable();
                if (table != null)
                {
                    return FindMac(table, addr.GetAddressBytes());
                }

                return ResolveViaArpCommand(ipv4);
            }
            catch
            {
                return null;
            }
        }

        // sysctl 로 ARP 테이블을 통째로 읽는다. 실패하면 null.
        private static byte[]? DumpArpTable()
        {
            int[] mib = { CtlNet, PfRoute, 0, AfInet, NetRtFlags, RtfLlInfo };
            nuint len = 0;
            if (sysctl(mib, (uint)mib.Length, null, ref len, IntPtr.Zero, 0) < 0) return null;
            if (len == 0) return Array.Empty<byte>();

            // 두 호출 사이에 테이블이 커질 수 있으므로 여유를 둔다.
            byte[] buf = new byte[len + len / 2];
            len = (nuint)buf.Length;
            if (sysctl(mib, (uint)mib.Length, buf, ref len, IntPtr.Zero, 0) < 0) return null;

            if ((int)len != buf.Length) Array.Resize(ref buf, (int)len);
            return buf;
        }

        // 라우팅 소켓 덤프 버퍼를 순회하며 targetIp(4바이트, 네트워크 순서)에 해당하는 MAC을 찾는다. 테스트용으로 분리.
        internal static string? FindMac(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> targetIp)
        {
            if (targetIp.Length != 4) return null;

            int pos = 0;
            while (pos + RtMsgHdrSize <= buffer.Length)
            {
                int msgLen = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(pos + OffRtmMsgLen, 2));
                if (msgLen < RtMsgHdrSize || pos + msgLen > buffer.Length) break;

                ReadOnlySpan<byte> record = buffer.Slice(pos, msgLen);
                int addrs = BinaryPrimitives.ReadInt32LittleEndian(record.Slice(OffRtmAddrs, 4));

                string? mac = ParseRecord(record.Slice(RtMsgHdrSize), addrs, targetIp);
                if (mac != null) return mac;

                pos += msgLen;
            }
            return null;
        }

        // 한 레코드의 sockaddr 영역을 RTA 비트 순서로 걸으며 DST(IP)·GATEWAY(링크 주소)를 추출한다.
        private static string? ParseRecord(ReadOnlySpan<byte> sockaddrs, int addrs, ReadOnlySpan<byte> targetIp)
        {
            bool ipMatched = false;
            string? mac = null;

            int pos = 0;
            for (int bit = 1; bit != 0 && bit <= addrs; bit <<= 1)
            {
                if ((addrs & bit) == 0) continue;
                if (pos >= sockaddrs.Length) break;

                int saLen = sockaddrs[pos];
                int stride = saLen == 0 ? 4 : (saLen + 3) & ~3;
                ReadOnlySpan<byte> sa = sockaddrs.Slice(pos, Math.Min(saLen, sockaddrs.Length - pos));

                if (bit == RtaDst)
                {
                    if (sa.Length < OffSinAddr + 4) return null;
                    ipMatched = sa.Slice(OffSinAddr, 4).SequenceEqual(targetIp);
                    if (!ipMatched) return null;
                }
                else if (bit == RtaGateway)
                {
                    if (sa.Length <= OffSdlAlen) return null;
                    int nlen = sa[OffSdlNlen];
                    int alen = sa[OffSdlAlen];
                    if (alen != 6) return null; // 불완전(incomplete) 항목
                    int start = OffSdlData + nlen;
                    if (start + 6 > sa.Length) return null;
                    mac = MacFormat.FromBytes(sa.Slice(start, 6));
                }

                pos += stride;
            }

            return ipMatched ? mac : null;
        }

        // 폴백: `arp -an` 출력 파싱. "? (192.168.0.1) at 0:23:aa:3a:82:ba on en0 ..."
        private static string? ResolveViaArpCommand(string ipv4)
        {
            string output = RunProcess("arp", "-an");
            return ParseArpCommandOutput(output, ipv4);
        }

        internal static string? ParseArpCommandOutput(string output, string ipv4)
        {
            if (string.IsNullOrEmpty(output)) return null;
            foreach (Match m in ArpLineRegex.Matches(output))
            {
                if (!string.Equals(m.Groups[1].Value, ipv4, StringComparison.Ordinal)) continue;
                return MacFormat.FromText(m.Groups[2].Value);
            }
            return null;
        }

        private static string RunProcess(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName, arguments)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using Process? p = Process.Start(psi);
                if (p == null) return "";
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(2000);
                return output;
            }
            catch
            {
                return "";
            }
        }
    }
}
