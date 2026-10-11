using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery
{
    // SNMP v2c GET(community 문자열, 기본 "public")으로 system 그룹의 sysDescr/sysObjectID/sysName/sysLocation을
    // 한 PDU에 묶어 질의한다. 네트워크 장비·프린터·NAS가 가장 정직하게 자기소개를 하는 경로다.
    public sealed class SnmpProbe : IIdentityProbe
    {
        public const int DefaultPort = 161;
        public const string OidSysDescr = "1.3.6.1.2.1.1.1.0";
        public const string OidSysObjectId = "1.3.6.1.2.1.1.2.0";
        public const string OidSysName = "1.3.6.1.2.1.1.5.0";
        public const string OidSysLocation = "1.3.6.1.2.1.1.6.0";

        private static readonly string[] Oids = { OidSysDescr, OidSysObjectId, OidSysName, OidSysLocation };

        private readonly string _community;
        private readonly int _port;

        public SnmpProbe(string community = "public") : this(community, DefaultPort) { }

        internal SnmpProbe(string community, int port)
        {
            _community = string.IsNullOrEmpty(community) ? "public" : community;
            _port = port;
        }

        public string Name => HostIdentity.SourceSnmp;

        public async Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                int requestId = Random.Shared.Next(1, int.MaxValue);
                byte[] request = SnmpCodec.BuildGetRequest(_community, requestId, Oids);
                Dictionary<string, string>? values = null;

                byte[]? reply = await UdpExchange.SendReceiveAsync(ip, _port, request, timeoutMs, attempts: 2, data =>
                {
                    // 요청 ID가 다른 응답(이전 시도의 늦은 응답 등)은 무시한다.
                    if (!SnmpCodec.TryParseResponse(data, out int id, out var parsed) || id != requestId) return false;
                    values = parsed;
                    return true;
                }, ct).ConfigureAwait(false);

                if (reply == null || values == null) return null;
                return FromValues(values);
            }
            catch
            {
                return null;
            }
        }

        // sysDescr가 없으면 실패로 본다(최소 한 개 OID 응답 필요).
        internal static HostIdentity? FromValues(IReadOnlyDictionary<string, string> values)
        {
            if (!values.TryGetValue(OidSysDescr, out string? sysDescr) || string.IsNullOrWhiteSpace(sysDescr)) return null;
            values.TryGetValue(OidSysObjectId, out string? sysObjectId);
            values.TryGetValue(OidSysName, out string? sysName);
            values.TryGetValue(OidSysLocation, out string? sysLocation);

            string? vendor = VendorFromObjectId(sysObjectId);
            string? osHint = OsHintFromDescr(sysDescr) ?? OsHintFromVendor(vendor);
            string? deviceHint = DeviceHintFromDescr(sysDescr) ?? DeviceHintFromVendor(vendor);

            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HostIdentity.AttrSnmpSysDescr] = sysDescr,
            };
            if (!string.IsNullOrWhiteSpace(sysObjectId)) attrs["snmp.sysobjectid"] = sysObjectId;
            if (!string.IsNullOrWhiteSpace(sysName)) attrs[HostIdentity.AttrSnmpSysName] = sysName.Trim();
            if (!string.IsNullOrWhiteSpace(sysLocation)) attrs["snmp.syslocation"] = sysLocation.Trim();
            if (vendor != null) attrs["snmp.vendor"] = vendor;

            return new HostIdentity(HostIdentity.SourceSnmp,
                string.IsNullOrWhiteSpace(sysName) ? null : sysName.Trim(),
                sysDescr.Length > 200 ? sysDescr.Substring(0, 200) : sysDescr,
                osHint, deviceHint, attrs);
        }

        // sysObjectID의 enterprise 번호(1.3.6.1.4.1.N) → 제조사
        private static readonly (int Enterprise, string Vendor)[] Enterprises =
        {
            (9, "Cisco"), (11, "HP"), (2636, "Juniper"), (14988, "MikroTik"), (6574, "Synology"),
            (311, "Microsoft"), (8072, "net-snmp"), (4413, "Broadcom"), (14823, "Aruba"), (25506, "H3C"),
            (2011, "Huawei"), (41112, "Ubiquiti"), (3808, "Lexmark"), (1248, "Epson"), (2435, "Brother"), (1602, "Canon"),
        };

        internal static string? VendorFromObjectId(string? sysObjectId)
        {
            if (string.IsNullOrEmpty(sysObjectId)) return null;
            const string prefix = "1.3.6.1.4.1.";
            string oid = sysObjectId.TrimStart('.');
            if (!oid.StartsWith(prefix, StringComparison.Ordinal)) return null;
            string rest = oid.Substring(prefix.Length);
            int dot = rest.IndexOf('.');
            string first = dot < 0 ? rest : rest.Substring(0, dot);
            if (!int.TryParse(first, out int enterprise)) return null;
            foreach (var (e, v) in Enterprises)
                if (e == enterprise) return v;
            return null;
        }

        private static readonly (string Keyword, string Os)[] OsKeywords =
        {
            ("cisco ios", "Cisco IOS"), ("ios-xe", "Cisco IOS"), ("ios xe", "Cisco IOS"), ("cisco nx-os", "Cisco NX-OS"),
            ("cisco adaptive security", "Cisco ASA"), ("junos", "JunOS"), ("routeros", "RouterOS"),
            ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("netbsd", "NetBSD"), ("linux", "Linux"),
            ("windows", "Windows"), ("darwin", "macOS"), ("mac os", "macOS"), ("vxworks", "VxWorks"),
            ("sunos", "Solaris"), ("solaris", "Solaris"), ("aix", "AIX"), ("hp-ux", "HP-UX"),
            ("ubiquiti", "Ubiquiti"), ("comware", "H3C Comware"), ("versatile routing platform", "Huawei VRP"),
            ("arubaos", "ArubaOS"), ("fortios", "FortiOS"), ("pan-os", "PAN-OS"), ("dsm", "Synology DSM"),
        };

        private static readonly string[] PrinterKeywords =
        {
            "printer", "laserjet", "officejet", "deskjet", "jetdirect", "imagerunner", "imageclass",
            "workforce", "ecotank", "mfc-", "dcp-", "hl-l", "lexmark", "xerox", "kyocera", "ricoh", "bizhub", "mfp",
        };

        internal static string? OsHintFromDescr(string descr)
        {
            string d = descr.ToLowerInvariant();
            foreach (var (k, os) in OsKeywords)
                if (d.Contains(k, StringComparison.Ordinal)) return os;
            foreach (string k in PrinterKeywords)
                if (d.Contains(k, StringComparison.Ordinal)) return "Printer firmware";
            return null;
        }

        private static string? OsHintFromVendor(string? vendor) => vendor switch
        {
            "net-snmp" => "Linux",
            "Microsoft" => "Windows",
            "Cisco" => "Cisco IOS",
            "Juniper" => "JunOS",
            "MikroTik" => "RouterOS",
            "Synology" => "Synology DSM",
            _ => null,
        };

        private static readonly (string Keyword, string Device)[] DeviceKeywords =
        {
            ("access point", "access point"), ("wireless ap", "access point"), ("unifi", "access point"),
            ("firewall", "firewall"), ("router", "router"), ("switch", "switch"), ("gateway", "router"),
            ("nas", "nas"), ("diskstation", "nas"), ("rackstation", "nas"), ("qnap", "nas"),
            ("camera", "camera"), ("ipcam", "camera"), ("nvr", "camera"), ("ups", "ups"),
        };

        internal static string? DeviceHintFromDescr(string descr)
        {
            string d = " " + descr.ToLowerInvariant() + " ";
            foreach (string k in PrinterKeywords)
                if (d.Contains(k, StringComparison.Ordinal)) return "printer";
            foreach (var (k, dev) in DeviceKeywords)
            {
                // "nas"/"ups" 같은 짧은 키워드는 단어 경계로만 맞춘다.
                bool hit = k.Length <= 3 ? d.Contains(" " + k + " ", StringComparison.Ordinal) : d.Contains(k, StringComparison.Ordinal);
                if (hit) return dev;
            }
            return null;
        }

        private static string? DeviceHintFromVendor(string? vendor) => vendor switch
        {
            "Cisco" or "Juniper" or "Broadcom" or "H3C" or "Huawei" or "Aruba" => "network device",
            "MikroTik" => "router",
            "Ubiquiti" => "access point",
            "Synology" => "nas",
            "Microsoft" => "pc/server",
            "net-snmp" => "server",
            "Lexmark" or "Epson" or "Brother" or "Canon" => "printer",
            "HP" => "HP device",
            _ => null,
        };
    }
}
