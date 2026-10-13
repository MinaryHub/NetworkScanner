using System;
using System.Globalization;
using System.Text;

namespace KetworkScanner.Discovery.Infrastructure
{
    // 인프라(라우터/스위치/OS 이웃 테이블) 발견기들이 공유하는 필드·키·출처 이름과 MAC 정규화 도우미.
    public static class InfrastructureFacts
    {
        // 어떤 장비/테이블이 이 호스트를 "알고 있다"는 사실. 값 = 에이전트 IP 또는 "os-neighbor-table"/"arp-probe".
        // 엔진은 이 사실이 있는 호스트를 핑에 답하지 않아도 살아 있는 것으로 볼 수 있다.
        public const string SeenByField = "seenBy";

        public const string SourceSnmpTable = "SNMP-table";
        public const string SourceNeighborTable = "neighbor-table";
        public const string SourceArpProbe = "ARP-probe";

        public const string SeenByNeighborTable = "os-neighbor-table";
        public const string SeenByArpProbe = "arp-probe";

        // 결과 사전의 합성 키. IP가 아닌 MAC/LLDP 이름/IPv6 주소로 묶인 사실은 엔진이 조인해서 쓴다.
        public const string MacKeyPrefix = "mac:";
        public const string LldpKeyPrefix = "lldp:";
        public const string V6KeyPrefix = "v6:";

        public static string MacKey(string normalizedMac) => MacKeyPrefix + normalizedMac;
        public static string LldpKey(string sysName) => LldpKeyPrefix + sysName;
        public static string V6Key(string address) => V6KeyPrefix + address;

        // 6바이트 → "AA-BB-CC-DD-EE-FF". 길이가 다르거나 전부 0이면 null.
        public static string? MacFromBytes(ReadOnlySpan<byte> mac)
        {
            if (mac.Length != 6) return null;
            bool allZero = true;
            foreach (byte b in mac) if (b != 0) { allZero = false; break; }
            if (allZero) return null;
            var sb = new StringBuilder(17);
            for (int i = 0; i < 6; i++)
            {
                if (i > 0) sb.Append('-');
                sb.Append(mac[i].ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        // "0:23:aa:3a:82:ba" / "00-23-AA-3A-82-BA" / "0023.aa3a.82ba" → "00-23-AA-3A-82-BA". 형식이 아니거나 전부 0이면 null.
        public static string? MacFromText(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            string s = raw.Trim();
            string[] octets;
            if (s.Contains('.') && !s.Contains(':') && !s.Contains('-'))
            {
                // Cisco 점 표기 "0023.aa3a.82ba"
                string hex = s.Replace(".", "");
                if (hex.Length != 12) return null;
                octets = new string[6];
                for (int i = 0; i < 6; i++) octets[i] = hex.Substring(i * 2, 2);
            }
            else
            {
                octets = s.Split(':', '-');
            }
            if (octets.Length != 6) return null;
            var bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                if (octets[i].Length == 0 || octets[i].Length > 2) return null;
                if (!byte.TryParse(octets[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i])) return null;
            }
            return MacFromBytes(bytes);
        }

        // 유니캐스트 MAC만 유효. 브로드캐스트/멀티캐스트(최하위 비트 1: 01:00:5e…, 33:33…)/전부 0은 제외.
        public static bool IsUsableMac(string? normalizedMac)
        {
            if (normalizedMac == null || normalizedMac.Length != 17) return false;
            if (normalizedMac == "FF-FF-FF-FF-FF-FF" || normalizedMac == "00-00-00-00-00-00") return false;
            if (!byte.TryParse(normalizedMac.AsSpan(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte first)) return false;
            return (first & 0x01) == 0;
        }
    }
}
