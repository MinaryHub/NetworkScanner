using System.Collections.Generic;

namespace KetworkScanner
{
    // OS 계열 추정. 확실한 식별(SNMP/NetBIOS/mDNS 힌트)이 있으면 그것을, 없으면 제조사·호스트명·열린 포트·TTL을 순서대로 본다.
    // TTL만으로는 폰/프린터/IoT가 전부 "Linux"로 보이고 Windows 외엔 구분이 안 되므로 마지막 근거로만 쓴다. 참고용 태그다.
    public static class OsGuesser
    {
        public static string FromTtl(int ttl)
        {
            if (ttl <= 0) return "";
            if (ttl <= 64) return "Linux/Unix";
            if (ttl <= 128) return "Windows";
            return Localization.T("dev.network");
        }

        public static string Guess(int ttl, string? vendor, string? openPorts, string? hostName, string? identityHint)
        {
            if (!string.IsNullOrWhiteSpace(identityHint)) return identityHint;

            string v = (vendor ?? "").ToLowerInvariant();
            string n = (hostName ?? "").ToLowerInvariant();
            var ports = new HashSet<int>(Network.ProbeExtensions.ParsePorts(openPorts));

            // 호스트명에 드러나는 기기(가장 구체적)
            if (n.Contains("iphone")) return "iOS";
            if (n.Contains("ipad")) return "iPadOS";
            if (n.Contains("macbook") || n.Contains("imac") || n.Contains("mac-mini") || n.Contains("macmini") || n.Contains("mac-studio")) return "macOS";
            if (n.Contains("android") || n.Contains("galaxy")) return "Android";
            if (n.StartsWith("desktop-") || n.StartsWith("laptop-") || n.StartsWith("win-")) return "Windows";
            if (n.Contains("raspberrypi") || n.StartsWith("pi-") || n.Contains("ubuntu") || n.Contains("debian") || n.Contains("centos")) return "Linux";

            // 포트 조합(서비스로 드러나는 OS)
            if (ports.Contains(62078)) return "iOS";                                   // lockdownd
            if (ports.Contains(5555) && !ports.Contains(445)) return "Android";          // adb
            if (ports.Contains(3389) || ports.Contains(135) || (ports.Contains(445) && !ports.Contains(22))) return "Windows";
            if (ports.Contains(548) || (ports.Contains(5000) && ports.Contains(7000))) return "macOS"; // AFP / AirPlay
            if (ports.Contains(9100) || ports.Contains(515) || ports.Contains(631)) return Localization.T("os.printer");

            // 제조사
            if (v.Contains("apple"))
            {
                if (ttl > 0 && ttl <= 64 && ports.Contains(22)) return "macOS";
                return "iOS/macOS";
            }
            if (v.Contains("samsung")) return ttl > 64 && ttl <= 128 ? "Windows" : "Android/Tizen";
            if (v.Contains("raspberry")) return "Linux";
            if (v.Contains("microsoft")) return "Windows";
            if (v.Contains("google")) return "Android/Google";
            if (v.Contains("amazon")) return "Fire OS/Linux";
            if (v.Contains("espressif") || v.Contains("texas instrument") || v.Contains("tuya") || v.Contains("shenzhen")) return Localization.T("os.embedded");
            if (v.Contains("hikvision") || v.Contains("dahua")) return Localization.T("os.embedded");
            if (v.Contains("cisco") || v.Contains("juniper") || v.Contains("mikrotik") || v.Contains("ubiquiti") || v.Contains("tp-link")
                || v.Contains("netgear") || v.Contains("d-link") || v.Contains("zyxel") || v.Contains("aruba") || v.Contains("hfr")) return Localization.T("dev.network");
            if (v.Contains("hewlett") || v.Contains("canon") || v.Contains("epson") || v.Contains("brother") || v.Contains("lexmark")) return Localization.T("os.printer");

            // 마지막으로 TTL
            if (ttl > 0 && ttl <= 64 && (ports.Contains(22) || ports.Contains(111) || ports.Contains(2049))) return "Linux/Unix";
            return FromTtl(ttl);
        }
    }
}
