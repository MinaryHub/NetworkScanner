using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Multicast
{
    // mDNS/DNS-SD 브라우징: 224.0.0.251:5353으로 _services._dns-sd._udp.local PTR을 물어 서비스 종류를 모은 뒤,
    // 종류별 PTR → 인스턴스의 SRV/TXT → 대상 호스트의 A/AAAA를 따라가며 IP별 사실(name/model/os/service…)을 만든다.
    // QU(유니캐스트 응답) 비트를 켜서 우리 소켓으로 답을 받고, 5353 멀티캐스트 응답도 함께 받는다.
    public sealed class MdnsBrowser : INetworkDiscovery
    {
        public const string Source = "mDNS";
        public static readonly IPAddress MulticastGroup = IPAddress.Parse("224.0.0.251");
        public const int Port = 5353;
        public const int MaxServiceTypes = 25;
        public const string ServiceEnumeration = "_services._dns-sd._udp.local";
        // RFC 6762는 mDNS 패킷의 IP TTL을 255로 요구한다(어차피 링크를 벗어나지 않는다).
        private const short Ttl = 255;
        private const int QuestionsPerPacket = 8;

        // 응답기가 서비스 열거에 답하지 않아도 항상 직접 묻는 종류.
        public static readonly string[] DefaultServiceTypes =
        {
            "_device-info._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
            "_smb._tcp.local", "_ipp._tcp.local", "_printer._tcp.local", "_http._tcp.local", "_ssh._tcp.local",
            "_googlecast._tcp.local", "_homekit._tcp.local", "_hap._tcp.local", "_spotify-connect._tcp.local",
            "_workstation._tcp.local", "_sonos._tcp.local", "_amzn-wplay._tcp.local",
        };

        public string Name => Source;

        public async Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
        {
            var responses = new List<DnsCodec.Response>();
            try
            {
                if (timeoutMs <= 0) return new Dictionary<string, IReadOnlyList<Fact>>();
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(timeoutMs);
                using var sockets = MulticastSocketSet.Open(MulticastGroup, Port, Ttl, listenOnGroupPort: true);
                var asked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // 1단계: 서비스 종류 열거(전체 시간의 1/3)
                var types = new List<string>(DefaultServiceTypes);
                await sockets.SendAsync(BuildQuery(new[] { (ServiceEnumeration, DnsCodec.TypePtr) }, unicastResponse: true), deadline.Token).ConfigureAwait(false);
                using (var phase1 = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token))
                {
                    phase1.CancelAfter(Math.Max(20, timeoutMs / 3));
                    while (!phase1.IsCancellationRequested)
                    {
                        MulticastSocketSet.Datagram? d = await sockets.ReceiveAsync(phase1.Token).ConfigureAwait(false);
                        if (d == null) break;
                        if (!DnsCodec.TryParseResponse(d.Value.Data, out DnsCodec.Response r) || !r.IsResponse) continue;
                        responses.Add(r);
                        foreach (DnsCodec.Record rec in r.Answers)
                        {
                            if (rec.Type != DnsCodec.TypePtr || !rec.Name.Equals(ServiceEnumeration, StringComparison.OrdinalIgnoreCase)) continue;
                            if (types.Count >= MaxServiceTypes) break;
                            if (!types.Contains(rec.Data, StringComparer.OrdinalIgnoreCase) && rec.Data.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) types.Add(rec.Data);
                        }
                    }
                }
                if (deadline.IsCancellationRequested) return FactsFromResponses(responses);

                // 2단계: 종류별 PTR 질의(두 번), 답이 올 때마다 SRV/TXT/A/AAAA 후속 질의
                var ptrQuestions = types.Select(t => (t, DnsCodec.TypePtr)).ToList();
                foreach (string t in types) asked.Add("PTR " + t);
                await SendBatchedAsync(sockets, ptrQuestions, deadline.Token).ConfigureAwait(false);
                Task resend = ResendAfterAsync(sockets, ptrQuestions, Math.Max(50, timeoutMs / 4), deadline.Token);

                while (!deadline.IsCancellationRequested)
                {
                    MulticastSocketSet.Datagram? d = await sockets.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                    if (d == null) break;
                    if (!DnsCodec.TryParseResponse(d.Value.Data, out DnsCodec.Response r) || !r.IsResponse) continue;
                    responses.Add(r);

                    List<(string, ushort)> followUps = FollowUpQuestions(responses, asked);
                    if (followUps.Count > 0) await SendBatchedAsync(sockets, followUps, deadline.Token).ConfigureAwait(false);
                }
                try { await resend.ConfigureAwait(false); } catch { }
            }
            catch (OperationCanceledException) { }
            catch { }
            return FactsFromResponses(responses);
        }

        private static async Task ResendAfterAsync(MulticastSocketSet sockets, List<(string, ushort)> questions, int delayMs, CancellationToken ct)
        {
            try
            {
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
                await SendBatchedAsync(sockets, questions, ct).ConfigureAwait(false);
            }
            catch { }
        }

        private static async Task SendBatchedAsync(MulticastSocketSet sockets, IReadOnlyList<(string, ushort)> questions, CancellationToken ct)
        {
            for (int i = 0; i < questions.Count; i += QuestionsPerPacket)
            {
                var slice = questions.Skip(i).Take(QuestionsPerPacket).ToArray();
                await sockets.SendAsync(BuildQuery(slice, unicastResponse: true), ct).ConfigureAwait(false);
            }
        }

        // 지금까지 모인 레코드를 보고, SRV/TXT가 없는 인스턴스와 A가 없는 SRV 대상에 대해 아직 안 물어본 질의를 만든다.
        internal static List<(string, ushort)> FollowUpQuestions(IEnumerable<DnsCodec.Response> responses, HashSet<string> asked)
        {
            var list = new List<(string, ushort)>();
            Graph g = Graph.Build(responses);
            foreach (Instance inst in g.Instances.Values)
            {
                if (inst.Target == null && asked.Add("SRV " + inst.FullName))
                {
                    list.Add((inst.FullName, DnsCodec.TypeSrv));
                    list.Add((inst.FullName, DnsCodec.TypeTxt));
                }
                if (inst.Target != null && !g.Hosts.ContainsKey(inst.Target) && asked.Add("A " + inst.Target))
                {
                    list.Add((inst.Target, DnsCodec.TypeA));
                    list.Add((inst.Target, DnsCodec.TypeAaaa));
                }
                if (list.Count >= 32) break;
            }
            return list;
        }

        // ---------- 질의 인코딩(여러 질문, QU 비트) ----------

        internal static byte[] BuildQuery(IReadOnlyList<(string Name, ushort Type)> questions, bool unicastResponse)
        {
            var buf = new List<byte>(128);
            AddU16(buf, 0);                     // mDNS 질의 ID는 0
            AddU16(buf, 0);                     // 표준 질의
            AddU16(buf, (ushort)questions.Count);
            AddU16(buf, 0); AddU16(buf, 0); AddU16(buf, 0);
            foreach (var (name, type) in questions)
            {
                foreach (string label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(label);
                    if (bytes.Length > 63) continue;
                    buf.Add((byte)bytes.Length);
                    buf.AddRange(bytes);
                }
                buf.Add(0);
                AddU16(buf, type);
                AddU16(buf, unicastResponse ? DnsCodec.ClassInUnicast : DnsCodec.ClassIn);
            }
            return buf.ToArray();
        }

        private static void AddU16(List<byte> buf, ushort v)
        {
            buf.Add((byte)(v >> 8));
            buf.Add((byte)v);
        }

        // ---------- 레코드 그래프 ----------

        internal sealed class Instance
        {
            public string FullName = "";       // "Living Room._airplay._tcp.local"
            public string Label = "";          // "Living Room"
            public string ServiceType = "";    // "_airplay._tcp.local"
            public string? Target;             // SRV 대상 호스트("host.local")
            public int Port;
            public Dictionary<string, string> Txt = new(StringComparer.OrdinalIgnoreCase);
        }

        internal sealed class Host
        {
            public string Name = "";           // "host.local"
            public List<string> A = new();
            public List<string> Aaaa = new();
        }

        internal sealed class Graph
        {
            public Dictionary<string, Instance> Instances = new(StringComparer.OrdinalIgnoreCase);
            public Dictionary<string, Host> Hosts = new(StringComparer.OrdinalIgnoreCase);

            public static Graph Build(IEnumerable<DnsCodec.Response> responses)
            {
                var g = new Graph();
                foreach (DnsCodec.Response r in responses)
                {
                    foreach (DnsCodec.Record rec in r.Answers.Concat(r.Authority).Concat(r.Additional))
                    {
                        switch (rec.Type)
                        {
                            case DnsCodec.TypePtr:
                                if (rec.Name.Equals(ServiceEnumeration, StringComparison.OrdinalIgnoreCase) || rec.Data.Length == 0) break;
                                if (TrySplitInstance(rec.Data, out string lbl, out string svc))
                                {
                                    Instance inst = g.GetInstance(rec.Data, lbl, svc);
                                    if (inst.ServiceType.Length == 0) inst.ServiceType = svc;
                                }
                                break;
                            case DnsCodec.TypeSrv:
                                {
                                    int colon = rec.Data.LastIndexOf(':');
                                    if (colon <= 0 || !TrySplitInstance(rec.Name, out string l2, out string s2)) break;
                                    Instance inst = g.GetInstance(rec.Name, l2, s2);
                                    inst.Target = rec.Data.Substring(0, colon).TrimEnd('.');
                                    if (int.TryParse(rec.Data.AsSpan(colon + 1), out int port)) inst.Port = port;
                                    break;
                                }
                            case DnsCodec.TypeTxt:
                                {
                                    if (!TrySplitInstance(rec.Name, out string l3, out string s3)) break;
                                    Instance inst = g.GetInstance(rec.Name, l3, s3);
                                    foreach (string kv in rec.Data.Split(';', StringSplitOptions.RemoveEmptyEntries))
                                    {
                                        int eq = kv.IndexOf('=');
                                        if (eq <= 0) continue;
                                        inst.Txt.TryAdd(kv.Substring(0, eq).Trim(), kv.Substring(eq + 1).Trim());
                                    }
                                    break;
                                }
                            case DnsCodec.TypeA:
                                if (rec.Data.Length > 0) g.GetHost(rec.Name).A.AddIfMissing(rec.Data);
                                break;
                            case DnsCodec.TypeAaaa:
                                if (rec.Data.Length > 0) g.GetHost(rec.Name).Aaaa.AddIfMissing(rec.Data);
                                break;
                        }
                    }
                }
                return g;
            }

            private Instance GetInstance(string full, string label, string svc)
            {
                if (!Instances.TryGetValue(full, out Instance? inst))
                    Instances[full] = inst = new Instance { FullName = full, Label = label, ServiceType = svc };
                return inst;
            }

            private Host GetHost(string name)
            {
                string n = name.TrimEnd('.');
                if (!Hosts.TryGetValue(n, out Host? h)) Hosts[n] = h = new Host { Name = n };
                return h;
            }
        }

        // "My Printer._ipp._tcp.local" → ("My Printer", "_ipp._tcp.local"). 서비스 종류 이름 자체("_ipp._tcp.local")는 false.
        internal static bool TrySplitInstance(string fullName, out string label, out string serviceType)
        {
            label = ""; serviceType = "";
            string n = fullName.TrimEnd('.');
            int proto = n.LastIndexOf("._tcp.local", StringComparison.OrdinalIgnoreCase);
            if (proto < 0) proto = n.LastIndexOf("._udp.local", StringComparison.OrdinalIgnoreCase);
            if (proto <= 0) return false;
            // 서비스 이름은 "._tcp" 바로 앞 라벨
            int svcStart = n.LastIndexOf('.', proto - 1);
            if (svcStart < 0) return false;    // 라벨 없음 → 서비스 종류 이름 자체
            serviceType = n.Substring(svcStart + 1);
            label = n.Substring(0, svcStart);
            return label.Length > 0 && serviceType.StartsWith('_');
        }

        // ---------- 사실 추출 ----------

        private static readonly Regex MacInBrackets = new(@"\[([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\]", RegexOptions.Compiled);
        private static readonly Regex MacPlain = new(@"^([0-9A-Fa-f]{12})@", RegexOptions.Compiled);

        internal static IReadOnlyDictionary<string, IReadOnlyList<Fact>> FactsFromResponses(IEnumerable<DnsCodec.Response> responses)
        {
            var result = new Dictionary<string, IReadOnlyList<Fact>>(StringComparer.Ordinal);
            Graph g = Graph.Build(responses);

            foreach (Host host in g.Hosts.Values)
            {
                if (host.A.Count == 0) continue;
                string shortName = StripLocal(host.Name);
                var instances = g.Instances.Values.Where(i =>
                    (i.Target != null && i.Target.Equals(host.Name, StringComparison.OrdinalIgnoreCase)) ||
                    // _device-info는 SRV가 없고 인스턴스 라벨이 호스트 이름이다.
                    (i.Target == null && i.ServiceType.StartsWith("_device-info.", StringComparison.OrdinalIgnoreCase)
                        && i.Label.Equals(shortName, StringComparison.OrdinalIgnoreCase))).ToList();

                foreach (string ip in host.A)
                {
                    var hf = new HostFacts(ip);
                    // 16진수 뭉치뿐인 자동 생성 호스트명(Chromecast "abcdef12-…" 등)은 TXT의 사용자 이름(fn)에 밀리도록 Medium.
                    hf.Add(FactFields.Name, shortName, Source, MdnsListExtensions.LooksGenerated(shortName) ? Confidence.Medium : Confidence.High);
                    foreach (string v6 in host.Aaaa) hf.Add(FactFields.Ipv6, v6, Source, Confidence.Low);
                    bool hasSmb = false, hasWorkstation = false;
                    // _device-info(모델/OS)를 먼저 처리해 같은 확신이면 그 값이 우선하게 한다.
                    foreach (Instance inst in instances.OrderBy(i => i.ServiceType.StartsWith("_device-info.", StringComparison.OrdinalIgnoreCase) ? 0 : 1))
                    {
                        ApplyInstance(hf, inst);
                        string t = ShortType(inst.ServiceType);
                        if (t == "_smb._tcp") hasSmb = true;
                        if (t == "_workstation._tcp") hasWorkstation = true;
                    }
                    if (hf.Best(FactFields.Os) == null)
                    {
                        if (hasWorkstation) hf.Add(FactFields.Os, "Linux", Source, Confidence.Low);
                        else if (hasSmb) hf.Add(FactFields.Os, "Windows", Source, Confidence.Low);
                    }
                    if (result.TryGetValue(ip, out IReadOnlyList<Fact>? existing)) hf.AddRange(existing);
                    result[ip] = hf.All;
                }
            }
            return result;
        }

        // 인스턴스 하나(서비스 종류 + TXT)에서 사실을 뽑는다.
        internal static void ApplyInstance(HostFacts hf, Instance inst)
        {
            string type = ShortType(inst.ServiceType);
            if (type.Length == 0) return;
            hf.Add(FactFields.Service, type, Source, Confidence.Low);
            Dictionary<string, string> txt = inst.Txt;

            switch (type)
            {
                case "_device-info._tcp":
                    ApplyAppleModel(hf, Get(txt, "model"));
                    if (txt.TryGetValue("osxvers", out string? osx))
                    {
                        hf.Add(FactFields.Os, "macOS", Source, Confidence.High);
                        string? ver = AppleModels.MapOsxVers(osx);
                        if (ver != null) hf.Add(FactFields.OsVersion, "macOS " + ver, Source, Confidence.High);
                    }
                    break;
                case "_airplay._tcp":
                    ApplyAppleModel(hf, Get(txt, "model"));
                    hf.Add(FactFields.Vendor, Get(txt, "manufacturer"), Source, Confidence.Medium);
                    hf.Add(FactFields.Mac, NormalizeMac(Get(txt, "deviceid")), Source, Confidence.Medium);
                    hf.Add(FactFields.Name, inst.Label, Source, Confidence.Medium);
                    break;
                case "_raop._tcp":
                    ApplyAppleModel(hf, Get(txt, "am"));
                    {
                        Match m = MacPlain.Match(inst.Label);
                        if (m.Success) hf.Add(FactFields.Mac, NormalizeMac(m.Groups[1].Value), Source, Confidence.Medium);
                        int at = inst.Label.IndexOf('@');
                        if (at >= 0 && at < inst.Label.Length - 1) hf.Add(FactFields.Name, inst.Label.Substring(at + 1), Source, Confidence.Low);
                    }
                    break;
                case "_companion-link._tcp":
                case "_rdlink._tcp":
                case "_sleep-proxy._udp":
                    hf.Add(FactFields.Vendor, "Apple", Source, Confidence.Low);
                    break;
                case "_googlecast._tcp":
                    hf.Add(FactFields.Vendor, "Google", Source, Confidence.Medium);
                    hf.Add(FactFields.Model, Get(txt, "md"), Source, Confidence.High);
                    hf.Add(FactFields.Name, Get(txt, "fn"), Source, Confidence.High); // 사용자가 붙인 이름이 호스트명보다 낫다
                    hf.Add(FactFields.DeviceType, "media", Source, Confidence.Medium);
                    break;
                case "_hap._tcp":
                case "_homekit._tcp":
                    hf.Add(FactFields.Model, Get(txt, "md"), Source, Confidence.High);
                    hf.Add(FactFields.DeviceType, "iot", Source, Confidence.Low);
                    break;
                case "_ipp._tcp":
                case "_ipps._tcp":
                case "_printer._tcp":
                case "_pdl-datastream._tcp":
                case "_scanner._tcp":
                case "_uscan._tcp":
                    hf.Add(FactFields.Model, Get(txt, "ty"), Source, Confidence.High);
                    hf.Add(FactFields.Model, Get(txt, "product")?.Trim('(', ')'), Source, Confidence.Medium);
                    hf.Add(FactFields.Model, Get(txt, "usb_MDL"), Source, Confidence.Medium);
                    hf.Add(FactFields.Vendor, Get(txt, "usb_MFG"), Source, Confidence.High);
                    hf.Add(FactFields.DeviceType, "printer", Source, Confidence.High);
                    break;
                case "_workstation._tcp":
                    {
                        Match m = MacInBrackets.Match(inst.Label);
                        if (m.Success) hf.Add(FactFields.Mac, NormalizeMac(m.Groups[1].Value), Source, Confidence.Medium);
                        hf.Add(FactFields.Os, "Linux", Source, Confidence.Low);
                    }
                    break;
                case "_sonos._tcp":
                    hf.Add(FactFields.Vendor, "Sonos", Source, Confidence.Medium);
                    hf.Add(FactFields.DeviceType, "media", Source, Confidence.Medium);
                    break;
                case "_amzn-wplay._tcp":
                    hf.Add(FactFields.Vendor, "Amazon", Source, Confidence.Low);
                    hf.Add(FactFields.DeviceType, "media", Source, Confidence.Low);
                    break;
                case "_spotify-connect._tcp":
                    hf.Add(FactFields.DeviceType, "media", Source, Confidence.Low);
                    break;
                case "_hue._tcp":
                    hf.Add(FactFields.Vendor, "Philips", Source, Confidence.Medium);
                    hf.Add(FactFields.DeviceType, "iot", Source, Confidence.Medium);
                    break;
                case "_miio._udp":
                    hf.Add(FactFields.Vendor, "Xiaomi", Source, Confidence.Medium);
                    hf.Add(FactFields.DeviceType, "iot", Source, Confidence.Low);
                    break;
                case "_matter._tcp":
                case "_matterc._udp":
                case "_esphomelib._tcp":
                case "_shelly._tcp":
                case "_ewelink._tcp":
                    hf.Add(FactFields.DeviceType, "iot", Source, Confidence.Low);
                    break;
                case "_rtsp._tcp":
                case "_axis-video._tcp":
                    hf.Add(FactFields.DeviceType, "camera", Source, Confidence.Low);
                    break;
            }
        }

        // model= 값이 Apple 식별자면 제품명(High)·원본 식별자(Medium)·제조사·종류를, 아니면 값을 그대로 model(High)로 넣는다.
        private static void ApplyAppleModel(HostFacts hf, string? id)
        {
            if (string.IsNullOrWhiteSpace(id)) return;
            if (AppleModels.TryDescribe(id, out AppleModels.Product p))
            {
                hf.Add(FactFields.Model, p.Name, Source, Confidence.High);
                if (!p.Name.Equals(id, StringComparison.OrdinalIgnoreCase)) hf.Add(FactFields.Model, id, Source, Confidence.Medium);
                hf.Add(FactFields.Vendor, "Apple", Source, Confidence.High);
                hf.Add(FactFields.DeviceType, p.DeviceType, Source, Confidence.Medium);
            }
            else
            {
                hf.Add(FactFields.Model, id, Source, Confidence.High);
            }
        }

        private static string? Get(Dictionary<string, string> txt, string key) => txt.TryGetValue(key, out string? v) && v.Length > 0 ? v : null;

        // "_airplay._tcp.local" → "_airplay._tcp"
        internal static string ShortType(string serviceType)
        {
            string t = serviceType.TrimEnd('.');
            if (t.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) t = t.Substring(0, t.Length - 6);
            return t;
        }

        internal static string StripLocal(string name)
        {
            string n = name.TrimEnd('.');
            if (n.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) n = n.Substring(0, n.Length - 6);
            return n;
        }

        // "aabbccddeeff" / "aa:bb:cc:dd:ee:ff" / "AA-BB-…" → "AA:BB:CC:DD:EE:FF"
        internal static string? NormalizeMac(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            string hex = new string(raw.Where(Uri.IsHexDigit).ToArray());
            if (hex.Length != 12) return null;
            return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2).ToUpperInvariant()));
        }
    }

    internal static class MdnsListExtensions
    {
        internal static bool LooksGenerated(string name)
            => System.Text.RegularExpressions.Regex.IsMatch(name, "^[0-9a-f]{4,}(-[0-9a-f]{2,})*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        public static void AddIfMissing(this List<string> list, string value)
        {
            if (!list.Contains(value, StringComparer.OrdinalIgnoreCase)) list.Add(value);
        }
    }
}
