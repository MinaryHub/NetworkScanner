using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace KetworkScanner.Discovery.Multicast
{
    // SSDP(UPnP) 발견: 239.255.255.250:1900으로 M-SEARCH(ssdp:all)를 두 번 보내고 timeout 동안 응답을 모은다.
    // 응답 헤더(SERVER/ST/USN)에서 서비스·OS·장비 종류를 뽑고, LOCATION의 장비 설명 XML을 받아
    // 이름/제조사/모델/시리얼을 보강한다. LOCATION은 응답한 IP 자신을 가리킬 때만 가져온다.
    public sealed class SsdpDiscovery : INetworkDiscovery
    {
        public const string Source = "SSDP";
        public static readonly IPAddress MulticastGroup = IPAddress.Parse("239.255.255.250");
        public const int Port = 1900;
        public const int MaxLocations = 20;
        public const int MaxDescriptionBytes = 64 * 1024;
        public const int DescriptionTimeoutMs = 2000;
        private const short Ttl = 2;

        public string Name => Source;

        public async Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
        {
            var hosts = new Dictionary<string, SsdpHost>(StringComparer.Ordinal);
            try
            {
                if (timeoutMs <= 0) return new Dictionary<string, IReadOnlyList<Fact>>();
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(timeoutMs);
                using var sockets = MulticastSocketSet.Open(MulticastGroup, Port, Ttl, listenOnGroupPort: false);

                byte[] msearch = BuildMSearch(mx: 2);
                await sockets.SendAsync(msearch, deadline.Token).ConfigureAwait(false);
                // 손실 대비 재전송(두 번째)
                Task resend = ResendAfterAsync(sockets, msearch, Math.Min(1000, Math.Max(50, timeoutMs / 3)), deadline.Token);

                while (!deadline.IsCancellationRequested)
                {
                    MulticastSocketSet.Datagram? d = await sockets.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                    if (d == null) break;
                    Accumulate(hosts, d.Value.From.Address, d.Value.Data);
                }
                try { await resend.ConfigureAwait(false); } catch { }
            }
            catch (OperationCanceledException) { }
            catch { }

            if (ct.IsCancellationRequested || hosts.Count == 0) return FactsFromHosts(hosts);

            await FetchDescriptionsAsync(hosts, ct).ConfigureAwait(false);
            return FactsFromHosts(hosts);
        }

        private static async Task ResendAfterAsync(MulticastSocketSet sockets, byte[] payload, int delayMs, CancellationToken ct)
        {
            try
            {
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
                await sockets.SendAsync(payload, ct).ConfigureAwait(false);
            }
            catch { }
        }

        // 응답 하나를 IP별 누적 정보에 합친다(ssdp:all은 장비·서비스마다 한 응답씩 오므로 집합으로 모은다).
        internal static void Accumulate(Dictionary<string, SsdpHost> hosts, IPAddress from, byte[] data)
        {
            if (from.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return;
            SsdpResponse? r = ParseResponse(data);
            if (r == null || !r.IsOk) return;
            string ip = from.ToString();
            if (!hosts.TryGetValue(ip, out SsdpHost? h)) hosts[ip] = h = new SsdpHost(ip);
            h.Merge(r);
        }

        // 모든 호스트의 LOCATION을 (전체 최대 MaxLocations개) 받아 설명 XML을 파싱해 넣는다.
        internal static async Task FetchDescriptionsAsync(Dictionary<string, SsdpHost> hosts, CancellationToken ct)
        {
            var jobs = new List<(SsdpHost host, Uri uri)>();
            foreach (SsdpHost h in hosts.Values)
            {
                foreach (string loc in h.Locations)
                {
                    if (jobs.Count >= MaxLocations) break;
                    if (IsLocationForHost(loc, h.Ip, out Uri? uri) && uri != null) jobs.Add((h, uri));
                }
            }
            if (jobs.Count == 0) return;

            await Task.WhenAll(jobs.Select(async j =>
            {
                string? xml = await SsdpDescriptionFetcher.FetchAsync(j.uri, DescriptionTimeoutMs, MaxDescriptionBytes, ct).ConfigureAwait(false);
                if (xml == null) return;
                DeviceDescription? desc = ParseDeviceDescription(xml);
                if (desc != null) lock (j.host) j.host.Descriptions.Add(desc);
            })).ConfigureAwait(false);
        }

        // LOCATION이 http(s)이고 호스트가 응답한 IP 자신일 때만 허용한다(다른 곳을 가리키는 URL은 무시).
        internal static bool IsLocationForHost(string location, string ip, out Uri? uri)
        {
            uri = null;
            if (!Uri.TryCreate(location.Trim(), UriKind.Absolute, out Uri? u)) return false;
            if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return false;
            if (!IPAddress.TryParse(u.Host.Trim('[', ']'), out IPAddress? host) || host.ToString() != ip) return false;
            uri = u;
            return true;
        }

        internal static IReadOnlyDictionary<string, IReadOnlyList<Fact>> FactsFromHosts(Dictionary<string, SsdpHost> hosts)
        {
            var result = new Dictionary<string, IReadOnlyList<Fact>>(StringComparer.Ordinal);
            foreach (SsdpHost h in hosts.Values)
            {
                IReadOnlyList<Fact> facts = FactsFromHost(h);
                if (facts.Count > 0) result[h.Ip] = facts;
            }
            return result;
        }

        internal static IReadOnlyList<Fact> FactsFromHost(SsdpHost h)
        {
            var hf = new HostFacts(h.Ip);
            // 설명 XML(High)을 먼저 넣어 같은 확신의 헤더 값보다 우선하게 한다.
            foreach (DeviceDescription d in h.Descriptions) hf.AddRange(FactsFromDescription(d));
            hf.AddRange(FactsFromHeaders(h.Servers, h.SearchTargets));
            return hf.All;
        }

        // ---------- M-SEARCH / 응답 파싱 ----------

        public static byte[] BuildMSearch(int mx)
        {
            string text = "M-SEARCH * HTTP/1.1\r\n" +
                          "HOST: 239.255.255.250:1900\r\n" +
                          "MAN: \"ssdp:discover\"\r\n" +
                          $"MX: {mx}\r\n" +
                          "ST: ssdp:all\r\n" +
                          "USER-AGENT: KetworkScanner/2.1 UPnP/1.1\r\n" +
                          "\r\n";
            return Encoding.ASCII.GetBytes(text);
        }

        public sealed class SsdpResponse
        {
            public string StatusLine = "";
            public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
            public bool IsOk => StatusLine.StartsWith("HTTP/1.", StringComparison.OrdinalIgnoreCase) && StatusLine.Contains(" 200", StringComparison.Ordinal);
            public string? Get(string name) => Headers.TryGetValue(name, out string? v) ? v : null;
        }

        internal static SsdpResponse? ParseResponse(byte[] data)
        {
            try { return ParseResponse(Encoding.UTF8.GetString(data)); }
            catch { return null; }
        }

        // "HTTP/1.1 200 OK\r\nHeader: value\r\n..." → 상태줄 + 헤더 사전(대소문자 무시). NOTIFY 같은 요청 줄도 받아들인다.
        internal static SsdpResponse? ParseResponse(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var r = new SsdpResponse();
            string[] lines = text.Split('\n');
            r.StatusLine = lines[0].TrimEnd('\r').Trim();
            if (r.StatusLine.Length == 0) return null;
            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i].TrimEnd('\r');
                if (line.Length == 0) break;
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                string key = line.Substring(0, colon).Trim();
                string val = line.Substring(colon + 1).Trim();
                if (key.Length == 0 || r.Headers.ContainsKey(key)) continue;
                r.Headers[key] = val;
            }
            return r;
        }

        // 헤더만으로 얻는 사실: SERVER → service(Medium)/os/vendor, ST·USN → deviceType.
        internal static IReadOnlyList<Fact> FactsFromHeaders(IEnumerable<string> servers, IEnumerable<string> searchTargets)
        {
            var hf = new HostFacts("");
            foreach (string server in servers)
            {
                hf.Add(FactFields.Service, server, Source, Confidence.Medium);
                foreach (Fact f in FactsFromServerHeader(server)) hf.Add(f.Field, f.Value, f.Source, f.Confidence);
            }
            foreach (string st in searchTargets)
            {
                string? type = MapDeviceType(st);
                if (type != null) hf.Add(FactFields.DeviceType, type, Source, Confidence.Medium);
            }
            return hf.All;
        }

        private static readonly (string Token, string Os)[] OsTokens =
        {
            ("microsoft-windows-nt", "Windows"), ("microsoft-windows", "Windows"), ("windows", "Windows"),
            ("linux", "Linux"), ("ubuntu", "Linux"), ("debian", "Linux"), ("fedora", "Linux"), ("android", "Android"),
            ("freebsd", "FreeBSD"), ("netbsd", "NetBSD"), ("openbsd", "OpenBSD"),
            ("darwin", "macOS"), ("macos", "macOS"), ("mac_os_x", "macOS"), ("macosx", "macOS"),
            ("vxworks", "VxWorks"), ("rtos", "RTOS"),
        };

        private static readonly (string Token, string Vendor, string? DeviceType)[] VendorTokens =
        {
            ("synology", "Synology", "nas"), ("qnap", "QNAP", "nas"), ("sonos", "Sonos", "media"), ("kodak", "Kodak", "printer"),
            ("samsung", "Samsung", null), ("lge", "LG", null), ("philips", "Philips", null), ("sony", "Sony", null),
            ("panasonic", "Panasonic", null), ("roku", "Roku", "media"), ("hisense", "Hisense", "media"), ("vizio", "Vizio", "media"),
            ("canon", "Canon", "printer"), ("hp", "HP", "printer"), ("epson", "Epson", "printer"), ("brother", "Brother", "printer"),
            ("xerox", "Xerox", "printer"), ("lexmark", "Lexmark", "printer"), ("ricoh", "Ricoh", "printer"), ("kyocera", "Kyocera", "printer"),
            ("netgear", "Netgear", "router"), ("asustek", "ASUS", "router"), ("asus", "ASUS", "router"), ("tp-link", "TP-Link", "router"),
            ("d-link", "D-Link", "router"), ("ubiquiti", "Ubiquiti", "router"), ("mikrotik", "MikroTik", "router"), ("zyxel", "Zyxel", "router"),
            ("fritz!box", "AVM", "router"), ("avm", "AVM", "router"), ("huawei", "Huawei", null), ("xiaomi", "Xiaomi", null),
            ("xbox", "Microsoft", "console"), ("playstation", "Sony", "console"),
            ("hikvision", "Hikvision", "camera"), ("dahua", "Dahua", "camera"), ("axis", "Axis", "camera"), ("reolink", "Reolink", "camera"),
            ("miniupnpd", "", "router"), ("mini-upnpd", "", "router"),
        };

        // "Linux/3.14.0 UPnP/1.0 Synology/1.0" 같은 SERVER 문자열의 토큰을 보고 os/osVersion/vendor/deviceType을 추정한다.
        internal static IReadOnlyList<Fact> FactsFromServerHeader(string server)
        {
            var hf = new HostFacts("");
            if (string.IsNullOrWhiteSpace(server)) return hf.All;
            foreach (string rawToken in server.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string token = rawToken.Trim('(', ')');
                int slash = token.IndexOf('/');
                string name = (slash >= 0 ? token.Substring(0, slash) : token).Trim();
                string version = slash >= 0 ? token.Substring(slash + 1).Trim() : "";
                string lower = name.ToLowerInvariant();
                if (lower.Length == 0) continue;

                foreach (var (t, os) in OsTokens)
                {
                    if (lower != t) continue;
                    hf.Add(FactFields.Os, os, Source, Confidence.Medium);
                    if (version.Length > 0 && Regex.IsMatch(version, @"^\d"))
                    {
                        string verName = os == "Linux" && lower != "linux" ? $"{name} {version}" : $"{os} {version}";
                        hf.Add(FactFields.OsVersion, verName, Source, Confidence.Low);
                    }
                    break;
                }
                foreach (var (t, vendor, type) in VendorTokens)
                {
                    if (lower != t) continue;
                    if (vendor.Length > 0) hf.Add(FactFields.Vendor, vendor, Source, Confidence.Medium);
                    if (type != null) hf.Add(FactFields.DeviceType, type, Source, Confidence.Low);
                    break;
                }
            }
            return hf.All;
        }

        private static readonly (string Needle, string Type)[] DeviceTypeNeedles =
        {
            ("InternetGatewayDevice", "router"), ("WANConnectionDevice", "router"), ("WANDevice", "router"),
            ("WANIPConnection", "router"), ("WANPPPConnection", "router"), ("Layer3Forwarding", "router"),
            ("WLANAccessPointDevice", "router"), ("WFADevice", "router"),
            ("MediaServer", "nas/media server"), ("ContentDirectory", "nas/media server"),
            ("MediaRenderer", "media"), ("AVTransport", "media"), ("RenderingControl", "media"),
            ("dial-multiscreen-org", "media"), ("roku:ecp", "media"), ("ZonePlayer", "media"),
            ("Printer", "printer"), ("PrintBasic", "printer"), ("Scanner", "printer"),
            ("Basic", "iot"), ("BinaryLight", "iot"), ("DimmableLight", "iot"), ("HVAC", "iot"), ("SensorManagement", "iot"),
            ("Camera", "camera"), ("DigitalSecurityCamera", "camera"),
        };

        // UPnP deviceType/ST/USN(urn:schemas-upnp-org:device:InternetGatewayDevice:1 등) → 장비 종류. 모르면 null.
        internal static string? MapDeviceType(string? upnpType)
        {
            if (string.IsNullOrWhiteSpace(upnpType)) return null;
            string s = upnpType;
            // uuid:...::urn:... 형태의 USN은 뒤쪽 urn 부분을 본다.
            int urn = s.IndexOf("urn:", StringComparison.OrdinalIgnoreCase);
            if (urn > 0) s = s.Substring(urn);
            foreach (var (needle, type) in DeviceTypeNeedles)
            {
                if (needle == "Basic")
                {
                    if (s.Contains(":device:Basic:", StringComparison.OrdinalIgnoreCase) || s.EndsWith(":device:Basic", StringComparison.OrdinalIgnoreCase)) return type;
                    continue;
                }
                if (s.Contains(needle, StringComparison.OrdinalIgnoreCase)) return type;
            }
            return null;
        }

        // ---------- 장비 설명 XML ----------

        public sealed record DeviceDescription(string? FriendlyName, string? Manufacturer, string? ModelName, string? ModelNumber,
            string? SerialNumber, string? DeviceType, string? ModelDescription, string? Udn);

        // 루트 <device>의 자식만 본다(네임스페이스 무시). DTD는 금지. 깨진 XML은 null.
        internal static DeviceDescription? ParseDeviceDescription(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml)) return null;
            try
            {
                var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersFromEntities = 1024 };
                using var reader = XmlReader.Create(new StringReader(xml), settings);
                XDocument doc = XDocument.Load(reader);
                XElement? device = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "device")
                                   ?? doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
                if (device == null) return null;

                string? Child(string local)
                {
                    string? v = device.Elements().FirstOrDefault(e => e.Name.LocalName == local)?.Value;
                    if (v == null) return null;
                    v = v.Trim();
                    return v.Length == 0 || v.Length > 200 ? null : v;
                }

                return new DeviceDescription(Child("friendlyName"), Child("manufacturer"), Child("modelName"), Child("modelNumber"),
                    Child("serialNumber"), Child("deviceType"), Child("modelDescription"), Child("UDN"));
            }
            catch
            {
                return null;
            }
        }

        internal static IReadOnlyList<Fact> FactsFromDescription(DeviceDescription d)
        {
            var hf = new HostFacts("");
            hf.Add(FactFields.Name, d.FriendlyName, Source, Confidence.Medium);
            hf.Add(FactFields.Vendor, d.Manufacturer, Source, Confidence.High);
            string? model = d.ModelName;
            if (!string.IsNullOrWhiteSpace(model) && !string.IsNullOrWhiteSpace(d.ModelNumber)
                && !model.Contains(d.ModelNumber, StringComparison.OrdinalIgnoreCase))
                model = $"{model} {d.ModelNumber}";
            hf.Add(FactFields.Model, model ?? d.ModelNumber, Source, Confidence.High);
            hf.Add(FactFields.Serial, d.SerialNumber, Source, Confidence.Medium);
            hf.Add(FactFields.DeviceType, MapDeviceType(d.DeviceType), Source, Confidence.High);
            hf.Add(FactFields.Description, d.ModelDescription, Source, Confidence.Low);
            return hf.All;
        }
    }

    // IP 하나에 대해 모인 SSDP 응답들의 집합.
    internal sealed class SsdpHost
    {
        public string Ip { get; }
        public HashSet<string> Servers { get; } = new(StringComparer.Ordinal);
        public HashSet<string> SearchTargets { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Locations { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<SsdpDiscovery.DeviceDescription> Descriptions { get; } = new();

        public SsdpHost(string ip) => Ip = ip;

        public void Merge(SsdpDiscovery.SsdpResponse r)
        {
            string? server = r.Get("SERVER");
            if (!string.IsNullOrWhiteSpace(server) && Servers.Count < 8) Servers.Add(server.Trim());
            foreach (string h in new[] { "ST", "USN", "NT" })
            {
                string? v = r.Get(h);
                if (!string.IsNullOrWhiteSpace(v) && SearchTargets.Count < 64) SearchTargets.Add(v.Trim());
            }
            string? loc = r.Get("LOCATION");
            if (!string.IsNullOrWhiteSpace(loc) && Locations.Count < 8) Locations.Add(loc.Trim());
        }
    }

    // 장비 설명 XML을 받는 HttpClient: 짧은 타임아웃, 크기 상한, 자체 서명 인증서 허용, 프록시 미사용.
    internal static class SsdpDescriptionFetcher
    {
        private static readonly Lazy<HttpClient> Client = new(() =>
        {
            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ConnectTimeout = TimeSpan.FromSeconds(2),
                SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
            };
            var c = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            c.DefaultRequestHeaders.UserAgent.ParseAdd("KetworkScanner/2.1");
            return c;
        });

        public static async Task<string?> FetchAsync(Uri uri, int timeoutMs, int maxBytes, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                using HttpResponseMessage resp = await Client.Value.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return null;
                using Stream s = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                var buf = new byte[maxBytes];
                int total = 0;
                while (total < maxBytes)
                {
                    int n = await s.ReadAsync(buf.AsMemory(total, maxBytes - total), cts.Token).ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
                return Encoding.UTF8.GetString(buf, 0, total);
            }
            catch
            {
                return null;
            }
        }
    }
}
