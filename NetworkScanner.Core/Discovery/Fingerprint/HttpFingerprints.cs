using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace NetworkScanner.Discovery.Fingerprint
{
    internal enum FpWhere { Any, Server, Title, Body }

    // 핑거프린트 한 줄: Pattern(정규식, 대소문자 무시)이 Where 영역에 맞으면 아래 값들을 Fact로 낸다.
    // ModelPattern의 1번 그룹은 model로 뽑는다.
    internal sealed record HttpFingerprint(
        string Pattern,
        FpWhere Where,
        string? Vendor = null,
        string? DeviceType = null,
        string? Os = null,
        string? OsVersion = null,
        string? Service = null,
        string? ModelPattern = null,
        Confidence Confidence = Confidence.Medium);

    // HTTP 응답(Server 헤더, <title>, 본문/realm/인증서 문자열)으로 제조사·장비 종류·OS를 알아내는 표. 순서대로 모두 적용한다.
    internal static class HttpFingerprints
    {
        private static readonly ConcurrentDictionary<string, Regex> RegexCache = new(StringComparer.Ordinal);

        public static readonly List<HttpFingerprint> Table = new()
        {
            // ---- 라우터/네트워크 ----
            new(@"RouterOS|\bmikrotik\b", FpWhere.Any, Vendor: "MikroTik", DeviceType: "router", Os: "MikroTik RouterOS", Confidence: Confidence.High),
            new(@"ipTIME", FpWhere.Any, Vendor: "EFM Networks (ipTIME)", DeviceType: "router", ModelPattern: @"ipTIME\s+([A-Z][A-Z0-9\-\+]{2,})", Confidence: Confidence.High),
            new(@"TP-?Link|\bTL-(?:WR|WA|SG|MR|WDR|WPA)[A-Z0-9]*|\bArcher\s+[A-Z]+\d", FpWhere.Any, Vendor: "TP-Link", DeviceType: "router", ModelPattern: @"\b((?:TL-[A-Z0-9]{3,}|Archer\s+[A-Z]+\d+[A-Z]*))"),
            new(@"\bASUS\b.*\bRT-[A-Z0-9]+|\bRT-[A-Z0-9]+.*\bASUS\b|ASUSWRT|ASUS Router|router\.asus\.com", FpWhere.Any, Vendor: "ASUS", DeviceType: "router", ModelPattern: @"\b(RT-[A-Z0-9]{3,}|GT-[A-Z0-9]{3,}|TUF-[A-Z0-9]{3,})"),
            new(@"\bNETGEAR\b|routerlogin\.net", FpWhere.Any, Vendor: "NETGEAR", DeviceType: "router"),
            new(@"\bD-Link\b|\bDIR-\d{3}", FpWhere.Any, Vendor: "D-Link", DeviceType: "router", ModelPattern: @"\b(DIR-\d{3,}[A-Z]*|DSL-\d{3,}[A-Z]*)"),
            new(@"\bZyXEL\b|\bZyxel\b", FpWhere.Any, Vendor: "Zyxel", DeviceType: "router"),
            new(@"\bLinksys\b", FpWhere.Any, Vendor: "Linksys", DeviceType: "router"),
            new(@"\bTenda\b", FpWhere.Any, Vendor: "Tenda", DeviceType: "router"),
            new(@"\bMiWiFi\b|miwifi\.com", FpWhere.Any, Vendor: "Xiaomi", DeviceType: "router"),
            new(@"\bHuawei\b", FpWhere.Any, Vendor: "Huawei", DeviceType: "network"),
            new(@"OpenWrt|\bLuCI\b", FpWhere.Any, Os: "OpenWrt", DeviceType: "router", Confidence: Confidence.High),
            new(@"DD-WRT", FpWhere.Any, Os: "DD-WRT", DeviceType: "router", Confidence: Confidence.High),
            new(@"pfSense", FpWhere.Any, Os: "pfSense (FreeBSD)", DeviceType: "firewall", Confidence: Confidence.High),
            new(@"OPNsense", FpWhere.Any, Os: "OPNsense (FreeBSD)", DeviceType: "firewall", Confidence: Confidence.High),
            new(@"\bFortiGate\b|\bFortinet\b|FortiOS", FpWhere.Any, Vendor: "Fortinet", DeviceType: "firewall", Os: "FortiOS"),
            new(@"SonicWall|SonicWALL", FpWhere.Any, Vendor: "SonicWall", DeviceType: "firewall"),
            new(@"WatchGuard", FpWhere.Any, Vendor: "WatchGuard", DeviceType: "firewall"),
            new(@"Palo Alto Networks|PAN-OS", FpWhere.Any, Vendor: "Palo Alto Networks", DeviceType: "firewall", Os: "PAN-OS"),
            new(@"\bSophos\b", FpWhere.Any, Vendor: "Sophos", DeviceType: "firewall"),
            new(@"\bCisco\b|cisco-IOS", FpWhere.Any, Vendor: "Cisco", DeviceType: "network"),
            new(@"\bMeraki\b", FpWhere.Any, Vendor: "Cisco Meraki", DeviceType: "network"),
            new(@"\bUbiquiti\b|\bUniFi\b|\bairOS\b|EdgeRouter|EdgeOS|EdgeSwitch", FpWhere.Any, Vendor: "Ubiquiti", DeviceType: "network"),
            new(@"\bUniFi\b", FpWhere.Any, Service: "UniFi"),
            new(@"\bAruba\b", FpWhere.Any, Vendor: "Aruba (HPE)", DeviceType: "network"),
            new(@"\bJuniper\b|Junos", FpWhere.Any, Vendor: "Juniper", DeviceType: "network", Os: "Junos"),

            // ---- NAS/스토리지 ----
            new(@"Synology|DiskStation|RackStation|\bDSM\b", FpWhere.Any, Vendor: "Synology", DeviceType: "nas", Os: "Synology DSM", Confidence: Confidence.High),
            new(@"\bQNAP\b|\bQTS\b|QuTS", FpWhere.Any, Vendor: "QNAP", DeviceType: "nas", Os: "QNAP QTS", Confidence: Confidence.High),
            new(@"TrueNAS|FreeNAS", FpWhere.Any, DeviceType: "nas", Os: "TrueNAS", Confidence: Confidence.High),
            new(@"OpenMediaVault|openmediavault", FpWhere.Any, DeviceType: "nas", Os: "OpenMediaVault (Debian)", Confidence: Confidence.High),
            new(@"\bUnraid\b", FpWhere.Any, DeviceType: "nas", Os: "Unraid", Confidence: Confidence.High),
            new(@"My Cloud|WD My", FpWhere.Any, Vendor: "Western Digital", DeviceType: "nas"),
            new(@"LinkStation|TeraStation|\bBuffalo\b", FpWhere.Any, Vendor: "Buffalo", DeviceType: "nas"),
            new(@"Asustor|\bADM\b", FpWhere.Title, Vendor: "ASUSTOR", DeviceType: "nas"),

            // ---- 카메라/NVR ----
            new(@"Hikvision|DVRDVS|DNVRS|\bDS-\d[A-Z0-9\-]+", FpWhere.Any, Vendor: "Hikvision", DeviceType: "camera", ModelPattern: @"\b(DS-\d[A-Z0-9\-]{3,})", Confidence: Confidence.High),
            new(@"\bDahua\b|DH-[A-Z]{2,}", FpWhere.Any, Vendor: "Dahua", DeviceType: "camera", Confidence: Confidence.High),
            new(@"AXIS Communications|Axis Communications", FpWhere.Any, Vendor: "Axis", DeviceType: "camera", Confidence: Confidence.High),
            new(@"\bReolink\b", FpWhere.Any, Vendor: "Reolink", DeviceType: "camera", Confidence: Confidence.High),
            new(@"\bFoscam\b", FpWhere.Any, Vendor: "Foscam", DeviceType: "camera", Confidence: Confidence.High),
            new(@"\bAmcrest\b", FpWhere.Any, Vendor: "Amcrest", DeviceType: "camera", Confidence: Confidence.High),
            new(@"\bHanwha\b|Wisenet", FpWhere.Any, Vendor: "Hanwha Vision", DeviceType: "camera", Confidence: Confidence.High),
            new(@"IP Camera|IPCam|Network Camera|NetCam", FpWhere.Title, DeviceType: "camera"),
            new(@"\bNVR\b|\bDVR\b", FpWhere.Title, DeviceType: "camera"),

            // ---- 프린터/복합기 ----
            new(@"LaserJet|OfficeJet|DeskJet|PageWide|Hewlett-Packard|HP-ChaiSOE|HP HTTP Server|Virata-EmWeb|HP ePrint|HP Color|HP Smart", FpWhere.Any, Vendor: "HP", DeviceType: "printer", ModelPattern: @"((?:Color\s+)?(?:LaserJet|OfficeJet|DeskJet|PageWide)[^<""\r\n,;]{0,30})", Confidence: Confidence.High),
            new(@"\bBrother\b|^Debut", FpWhere.Any, Vendor: "Brother", DeviceType: "printer", ModelPattern: @"\b((?:HL|MFC|DCP)-[A-Z0-9]{3,})", Confidence: Confidence.High),
            new(@"\bEPSON\b", FpWhere.Any, Vendor: "Epson", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bCanon\b|CANON HTTP Server", FpWhere.Any, Vendor: "Canon", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bKyocera\b|KYOCERA", FpWhere.Any, Vendor: "Kyocera", DeviceType: "printer", Confidence: Confidence.High),
            new(@"Konica Minolta|bizhub", FpWhere.Any, Vendor: "Konica Minolta", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bRICOH\b|Web Image Monitor", FpWhere.Any, Vendor: "Ricoh", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bXerox\b|CentreWare", FpWhere.Any, Vendor: "Xerox", DeviceType: "printer", Confidence: Confidence.High),
            new(@"SyncThru|Samsung Printer", FpWhere.Any, Vendor: "Samsung", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bLexmark\b", FpWhere.Any, Vendor: "Lexmark", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bSindoh\b", FpWhere.Any, Vendor: "Sindoh", DeviceType: "printer", Confidence: Confidence.High),
            new(@"\bOKI\b", FpWhere.Title, Vendor: "OKI", DeviceType: "printer"),
            new(@"\bCUPS\b", FpWhere.Any, Service: "CUPS", Os: "Linux/Unix", Confidence: Confidence.Low),
            new(@"Printer Status|\bPrinter\b", FpWhere.Title, DeviceType: "printer", Confidence: Confidence.Low),

            // ---- VoIP ----
            new(@"Grandstream", FpWhere.Any, Vendor: "Grandstream", DeviceType: "voip", Confidence: Confidence.High),
            new(@"\bYealink\b", FpWhere.Any, Vendor: "Yealink", DeviceType: "voip", Confidence: Confidence.High),
            new(@"\bPolycom\b|\bPoly\b", FpWhere.Any, Vendor: "Poly (Polycom)", DeviceType: "voip"),
            new(@"\bSnom\b", FpWhere.Any, Vendor: "Snom", DeviceType: "voip"),

            // ---- 서버/가상화/BMC ----
            new(@"Proxmox", FpWhere.Any, Os: "Proxmox VE", DeviceType: "server", Service: "Proxmox VE", Confidence: Confidence.High),
            new(@"VMware ESXi|ESXi", FpWhere.Any, Vendor: "VMware", Os: "VMware ESXi", DeviceType: "server", Confidence: Confidence.High),
            new(@"vCenter|vSphere", FpWhere.Any, Vendor: "VMware", Service: "vSphere", DeviceType: "server"),
            new(@"\biDRAC\b", FpWhere.Any, Vendor: "Dell", DeviceType: "bmc", Service: "iDRAC", Confidence: Confidence.High),
            new(@"\biLO\b|Integrated Lights-Out", FpWhere.Any, Vendor: "HPE", DeviceType: "bmc", Service: "iLO", Confidence: Confidence.High),
            new(@"Supermicro|\bIPMI\b", FpWhere.Any, DeviceType: "bmc"),
            new(@"Supermicro", FpWhere.Any, Vendor: "Supermicro"),
            new(@"\bPortainer\b", FpWhere.Any, Service: "Portainer", Os: "Linux", DeviceType: "server"),
            new(@"Nginx Proxy Manager", FpWhere.Any, Service: "Nginx Proxy Manager", Os: "Linux"),

            // ---- 홈/미디어/IoT ----
            new(@"Home Assistant", FpWhere.Any, Service: "Home Assistant", Os: "Linux", DeviceType: "server", Confidence: Confidence.High),
            new(@"\bJellyfin\b", FpWhere.Any, Service: "Jellyfin", DeviceType: "media server", Confidence: Confidence.High),
            new(@"\bPlex\b", FpWhere.Any, Service: "Plex", DeviceType: "media server", Confidence: Confidence.High),
            new(@"\bKodi\b", FpWhere.Any, Service: "Kodi", DeviceType: "media server"),
            new(@"\bEmby\b", FpWhere.Any, Service: "Emby", DeviceType: "media server"),
            new(@"\bSonos\b", FpWhere.Any, Vendor: "Sonos", DeviceType: "media"),
            new(@"\bRoku\b", FpWhere.Any, Vendor: "Roku", DeviceType: "media"),
            new(@"Philips hue|\bhue\b.*bridge", FpWhere.Any, Vendor: "Philips (Signify)", DeviceType: "iot"),
            new(@"\bTasmota\b", FpWhere.Any, Os: "Tasmota", DeviceType: "iot", Confidence: Confidence.High),
            new(@"ESPHome|ESP8266|ESP32|ESPAsyncWebServer", FpWhere.Any, Vendor: "Espressif", DeviceType: "iot"),
            new(@"\bShelly\b", FpWhere.Any, Vendor: "Shelly", DeviceType: "iot"),
            new(@"\bTizen\b|Samsung TV", FpWhere.Any, Vendor: "Samsung", DeviceType: "tv"),
            new(@"\bwebOS\b", FpWhere.Any, Vendor: "LG", DeviceType: "tv"),
            new(@"Raspberry Pi", FpWhere.Any, Vendor: "Raspberry Pi", Os: "Linux", OsVersion: "Raspberry Pi OS"),
            new(@"Pi-hole", FpWhere.Any, Service: "Pi-hole", Os: "Linux", Confidence: Confidence.High),

            // ---- Server 헤더 → OS ----
            new(@"Microsoft-HTTPAPI", FpWhere.Server, Os: "Windows", Confidence: Confidence.High),
            new(@"Microsoft-IIS", FpWhere.Server, Os: "Windows", Service: "IIS", Confidence: Confidence.Medium),
            new(@"\(Ubuntu\)", FpWhere.Server, Os: "Linux", OsVersion: "Ubuntu"),
            new(@"\(Debian\)", FpWhere.Server, Os: "Linux", OsVersion: "Debian"),
            new(@"\(Raspbian\)", FpWhere.Server, Os: "Linux", OsVersion: "Raspberry Pi OS", Vendor: "Raspberry Pi"),
            new(@"\(CentOS\)|\(Red Hat(?: Enterprise Linux)?\)|\(Rocky Linux\)|\(AlmaLinux\)|\(Oracle\)", FpWhere.Server, Os: "Linux", OsVersion: "RHEL 계열"),
            new(@"\(Fedora\)", FpWhere.Server, Os: "Linux", OsVersion: "Fedora"),
            new(@"\(FreeBSD\)", FpWhere.Server, Os: "FreeBSD"),
            new(@"\(Win64\)|\(Win32\)|\(Windows\)", FpWhere.Server, Os: "Windows"),
            new(@"\(Unix\)", FpWhere.Server, Os: "Linux/Unix", Confidence: Confidence.Low),
            new(@"^lighttpd", FpWhere.Server, Os: "Embedded Linux", Confidence: Confidence.Low),
            new(@"GoAhead|mini_httpd|micro_httpd|^Boa/|thttpd|uhttpd|RomPager|Mbedthis|Embedthis|Allegro", FpWhere.Server, Os: "Embedded Linux", DeviceType: "embedded"),
            new(@"\bASP\.NET\b", FpWhere.Body, Os: "Windows", Confidence: Confidence.Low),
        };

        // server/title/body 중 해당 영역에 패턴이 맞는 항목의 값을 Fact로 모은다.
        public static IReadOnlyList<Fact> Match(string? server, string? title, string? body, string source = HttpProbe.Source)
        {
            var facts = new FactList(source);
            foreach (HttpFingerprint fp in Table)
            {
                string? hit = null;
                foreach (string? text in Texts(fp.Where, server, title, body))
                {
                    if (!string.IsNullOrEmpty(text) && Rx(fp.Pattern).IsMatch(text)) { hit = text; break; }
                }
                if (hit == null) continue;

                facts.Add(FactFields.Vendor, fp.Vendor, fp.Confidence);
                facts.Add(FactFields.DeviceType, fp.DeviceType, fp.Confidence);
                facts.Add(FactFields.Os, fp.Os, fp.Confidence);
                facts.Add(FactFields.OsVersion, fp.OsVersion, fp.Confidence);
                facts.Add(FactFields.Service, fp.Service, fp.Confidence);
                if (fp.ModelPattern != null)
                {
                    foreach (string? text in new[] { title, body, server })
                    {
                        if (string.IsNullOrEmpty(text)) continue;
                        Match m = Rx(fp.ModelPattern).Match(text);
                        if (m.Success && m.Groups.Count > 1)
                        {
                            facts.Add(FactFields.Model, m.Groups[1].Value.Trim(), fp.Confidence);
                            break;
                        }
                    }
                }
            }
            return facts.ToList();
        }

        private static IEnumerable<string?> Texts(FpWhere where, string? server, string? title, string? body)
        {
            switch (where)
            {
                case FpWhere.Server: yield return server; break;
                case FpWhere.Title: yield return title; break;
                case FpWhere.Body: yield return body; break;
                default: yield return title; yield return server; yield return body; break;
            }
        }

        private static Regex Rx(string pattern)
            => RegexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)));
    }
}
