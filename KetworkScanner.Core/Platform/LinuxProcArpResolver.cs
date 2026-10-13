using System.Net;
using System.Runtime.Versioning;

namespace KetworkScanner.Platform
{
    // /proc/net/arp 를 읽어 MAC을 조회한다. 형식:
    //   IP address       HW type     Flags       HW address            Mask     Device
    //   192.168.0.1      0x1         0x2         00:11:22:33:44:55     *        eth0
    // Flags 의 0x2 비트(ATF_COM, 완료)가 켜진 항목만 유효하다.
    [SupportedOSPlatform("linux")]
    public sealed class LinuxProcArpResolver : IArpResolver
    {
        private const string ProcArpPath = "/proc/net/arp";
        private const int AtfCom = 0x2;

        public string? Resolve(string ipv4)
        {
            try
            {
                if (!IPAddress.TryParse(ipv4, out _)) return null;
                string text = File.ReadAllText(ProcArpPath);
                return FindMac(text, ipv4);
            }
            catch
            {
                return null;
            }
        }

        // 파일 텍스트에서 ip 에 해당하는 완료된 항목의 MAC을 찾는다. 테스트용으로 분리.
        internal static string? FindMac(string procArpText, string ipv4)
        {
            if (string.IsNullOrEmpty(procArpText)) return null;

            string[] lines = procArpText.Split('\n');
            // 첫 줄은 헤더
            for (int i = 1; i < lines.Length; i++)
            {
                string[] cols = lines[i].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 4) continue;
                if (!string.Equals(cols[0], ipv4, StringComparison.Ordinal)) continue;

                if (!TryParseHexFlags(cols[2], out int flags) || (flags & AtfCom) == 0) continue;

                return MacFormat.FromText(cols[3]);
            }
            return null;
        }

        private static bool TryParseHexFlags(string s, out int flags)
        {
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            return int.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out flags);
        }
    }
}
