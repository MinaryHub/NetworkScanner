using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Infrastructure
{
    // 라우터/스위치의 SNMP 테이블에서 호스트 사실을 캔다.
    //  - ARP(ipNetToPhysical / ipNetToMedia): IPv4 → MAC, 그리고 "이 장비가 이 호스트를 안다"(seenBy)
    //  - 브리지 FDB(dot1dTpFdb / dot1qTpFdb) + ifName: MAC → 스위치 포트 (키 "mac:AA-BB-…")
    //  - LLDP 원격 테이블: 이웃 장비 이름/설명/포트 (키 "lldp:<sysName>")
    // 에이전트가 답하지 않으면 조용히 건너뛴다(예외 없음, 디버그 로그만).
    public sealed class SnmpInfrastructureDiscovery : INetworkDiscovery
    {
        public const string OidSysName = "1.3.6.1.2.1.1.5.0";
        public const string OidIpNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4"; // index: ifIndex.addrType.addrLen.addr…
        public const string OidIpNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2";    // index: ifIndex.a.b.c.d
        public const string OidDot1dTpFdbPort = "1.3.6.1.2.1.17.4.3.1.2";           // index: 6 MAC 옥텟 → bridge port
        public const string OidDot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2";       // index: vlan.6 MAC 옥텟 → bridge port
        public const string OidDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";     // index: bridge port → ifIndex
        public const string OidIfName = "1.3.6.1.2.1.31.1.1.1.1";                   // index: ifIndex
        public const string OidIfDescr = "1.3.6.1.2.1.2.2.1.2";                     // index: ifIndex
        public const string OidLldpRemTable = "1.0.8802.1.1.2.1.4.1.1";             // column.timeMark.localPortNum.remIndex
        public const string OidLldpLocPortId = "1.0.8802.1.1.2.1.3.7.1.3";          // index: localPortNum

        // lldpRemTable 열 번호
        private const int LldpColChassisIdSubtype = 4, LldpColChassisId = 5, LldpColPortIdSubtype = 6, LldpColPortId = 7,
            LldpColPortDesc = 8, LldpColSysName = 9, LldpColSysDesc = 10;

        private readonly (IPAddress Ip, string Community)[] _agents;
        private readonly SnmpWalker _walker;

        public SnmpInfrastructureDiscovery(IEnumerable<(IPAddress Ip, string Community)> agents) : this(agents, new SnmpWalker()) { }

        internal SnmpInfrastructureDiscovery(IEnumerable<(IPAddress Ip, string Community)> agents, SnmpWalker walker)
        {
            _agents = agents
                .Where(a => a.Ip != null)
                .GroupBy(a => a.Ip)
                .Select(g => (g.Key, string.IsNullOrEmpty(g.First().Community) ? "public" : g.First().Community))
                .ToArray();
            _walker = walker;
        }

        public string Name => InfrastructureFacts.SourceSnmpTable;

        public IReadOnlyList<(IPAddress Ip, string Community)> Agents => _agents;

        public async Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
        {
            var results = new List<AgentTables>();
            if (_agents.Length > 0)
            {
                int perRequestMs = Math.Clamp(timeoutMs, 100, 2000);
                AgentTables?[] collected = await Task.WhenAll(_agents.Select(a => CollectAsync(a.Ip, a.Community, perRequestMs, ct))).ConfigureAwait(false);
                results.AddRange(collected.Where(r => r != null)!);
            }
            return BuildFacts(results);
        }

        // ---- 에이전트 하나의 테이블 수집 ----

        internal sealed class AgentTables
        {
            public IPAddress Agent = IPAddress.None;
            public string SysName = "";
            public string Label => string.IsNullOrEmpty(SysName) ? Agent.ToString() : SysName;
            public Dictionary<string, string> ArpV4 = new(StringComparer.Ordinal);               // ip → MAC
            public Dictionary<string, string> ArpV6 = new(StringComparer.OrdinalIgnoreCase);     // ipv6 → MAC
            public Dictionary<string, int> MacToBridgePort = new(StringComparer.Ordinal);       // MAC → bridge port
            public Dictionary<int, int> BridgePortToIfIndex = new();
            public Dictionary<int, string> IfNames = new();
            public Dictionary<int, string> LocalPortIds = new();                                 // LLDP local port num → id
            public List<LldpNeighbor> Lldp = new();

            public string PortLabel(int bridgePort)
            {
                if (BridgePortToIfIndex.TryGetValue(bridgePort, out int ifIndex) && IfNames.TryGetValue(ifIndex, out string? n) && !string.IsNullOrEmpty(n)) return n;
                if (IfNames.TryGetValue(bridgePort, out string? direct) && !string.IsNullOrEmpty(direct) && BridgePortToIfIndex.Count == 0) return direct;
                return "port " + bridgePort;
            }

            public string LocalPortLabel(int localPortNum)
            {
                if (LocalPortIds.TryGetValue(localPortNum, out string? id) && !string.IsNullOrEmpty(id)) return id;
                if (IfNames.TryGetValue(localPortNum, out string? n) && !string.IsNullOrEmpty(n)) return n;
                return "port " + localPortNum;
            }
        }

        internal sealed class LldpNeighbor
        {
            public int LocalPortNum;
            public int ChassisIdSubtype;
            public string ChassisId = "";
            public int PortIdSubtype;
            public string PortId = "";
            public string PortDesc = "";
            public string SysName = "";
            public string SysDesc = "";
            public string? ChassisMac; // chassisIdSubtype=macAddress(4)일 때
        }

        internal async Task<AgentTables?> CollectAsync(IPAddress agent, string community, int perRequestMs, CancellationToken ct)
        {
            try
            {
                var t = new AgentTables { Agent = agent };

                // sysName GET이 생존 확인을 겸한다.
                IReadOnlyDictionary<string, string>? sys = await _walker.GetAsync(agent, community, new[] { OidSysName }, perRequestMs, ct).ConfigureAwait(false);
                if (sys == null)
                {
                    AppLogger.LogDebug(nameof(SnmpInfrastructureDiscovery), $"{agent}: SNMP 응답 없음(community '{community}') — 건너뜀");
                    return null;
                }
                if (sys.TryGetValue(OidSysName, out string? name)) t.SysName = name.Trim();

                // ARP: ipNetToPhysical(IPv4/IPv6) → 없으면 ipNetToMedia(IPv4)
                var phys = await _walker.WalkAsync(agent, community, OidIpNetToPhysicalPhysAddress, perRequestMs, ct).ConfigureAwait(false);
                ParseIpNetToPhysical(phys, t.ArpV4, t.ArpV6);
                if (t.ArpV4.Count == 0)
                {
                    var media = await _walker.WalkAsync(agent, community, OidIpNetToMediaPhysAddress, perRequestMs, ct).ConfigureAwait(false);
                    ParseIpNetToMedia(media, t.ArpV4);
                }

                // 인터페이스 이름: ifName → 없으면 ifDescr
                ParseIntIndexedStrings(await _walker.WalkAsync(agent, community, OidIfName, perRequestMs, ct).ConfigureAwait(false), OidIfName, t.IfNames);
                if (t.IfNames.Count == 0)
                    ParseIntIndexedStrings(await _walker.WalkAsync(agent, community, OidIfDescr, perRequestMs, ct).ConfigureAwait(false), OidIfDescr, t.IfNames);

                // 브리지 FDB
                ParseBridgePortIfIndex(await _walker.WalkAsync(agent, community, OidDot1dBasePortIfIndex, perRequestMs, ct).ConfigureAwait(false), t.BridgePortToIfIndex);
                ParseFdb(await _walker.WalkAsync(agent, community, OidDot1dTpFdbPort, perRequestMs, ct).ConfigureAwait(false), OidDot1dTpFdbPort, vlanIndexed: false, t.MacToBridgePort);
                ParseFdb(await _walker.WalkAsync(agent, community, OidDot1qTpFdbPort, perRequestMs, ct).ConfigureAwait(false), OidDot1qTpFdbPort, vlanIndexed: true, t.MacToBridgePort);

                // LLDP
                var rem = await _walker.WalkAsync(agent, community, OidLldpRemTable, perRequestMs, ct).ConfigureAwait(false);
                t.Lldp = AssembleLldp(rem);
                if (t.Lldp.Count > 0)
                    ParseIntIndexedStrings(await _walker.WalkAsync(agent, community, OidLldpLocPortId, perRequestMs, ct).ConfigureAwait(false), OidLldpLocPortId, t.LocalPortIds);

                AppLogger.LogDebug(nameof(SnmpInfrastructureDiscovery),
                    $"{agent} ({t.Label}): arp={t.ArpV4.Count}/{t.ArpV6.Count} fdb={t.MacToBridgePort.Count} if={t.IfNames.Count} lldp={t.Lldp.Count}");
                return t;
            }
            catch (Exception ex)
            {
                AppLogger.LogDebug(nameof(SnmpInfrastructureDiscovery), $"{agent}: 수집 실패 — {ex.Message}");
                return null;
            }
        }

        // ---- 인덱스/행 해석 (순수 함수, 테스트 대상) ----

        // ipNetToPhysicalPhysAddress 인덱스: ifIndex.addrType.addrLen.addr…  (addrType 1/3=IPv4, 2/4=IPv6)
        internal static bool TryParseIpNetToPhysicalIndex(string oid, out IPAddress? ip)
        {
            ip = null;
            long[]? s = OidUtil.Suffix(oid, OidIpNetToPhysicalPhysAddress);
            if (s == null || s.Length < 4) return false;
            long type = s[1], len = s[2];
            if (len < 0 || s.Length < 3 + len) return false;
            int need = type is 1 or 3 ? 4 : type is 2 or 4 ? 16 : -1;
            if (need < 0 || len < need) return false;
            var bytes = new byte[need];
            for (int i = 0; i < need; i++)
            {
                if (s[3 + i] < 0 || s[3 + i] > 255) return false;
                bytes[i] = (byte)s[3 + i];
            }
            ip = new IPAddress(bytes);
            return true;
        }

        // ipNetToMediaPhysAddress 인덱스: ifIndex.a.b.c.d
        internal static bool TryParseIpNetToMediaIndex(string oid, out IPAddress? ip)
        {
            ip = null;
            long[]? s = OidUtil.Suffix(oid, OidIpNetToMediaPhysAddress);
            if (s == null || s.Length != 5) return false;
            var bytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                if (s[1 + i] < 0 || s[1 + i] > 255) return false;
                bytes[i] = (byte)s[1 + i];
            }
            ip = new IPAddress(bytes);
            return true;
        }

        // dot1dTpFdbPort(인덱스 = MAC 6옥텟) / dot1qTpFdbPort(인덱스 = vlan.MAC 6옥텟) → 정규화 MAC
        internal static string? ParseFdbIndexMac(string oid, string baseOid, bool vlanIndexed)
        {
            long[]? s = OidUtil.Suffix(oid, baseOid);
            int expected = vlanIndexed ? 7 : 6;
            if (s == null || s.Length != expected) return null;
            var bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                long v = s[s.Length - 6 + i];
                if (v < 0 || v > 255) return null;
                bytes[i] = (byte)v;
            }
            return InfrastructureFacts.MacFromBytes(bytes);
        }

        internal static void ParseIpNetToPhysical(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows,
            Dictionary<string, string> v4, Dictionary<string, string> v6)
        {
            foreach (var row in rows)
            {
                string? mac = InfrastructureFacts.MacFromBytes(row.Raw);
                if (!InfrastructureFacts.IsUsableMac(mac) || !TryParseIpNetToPhysicalIndex(row.Oid, out IPAddress? ip) || ip == null) continue;
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) v4[ip.ToString()] = mac!;
                else v6[ip.ToString()] = mac!;
            }
        }

        internal static void ParseIpNetToMedia(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows, Dictionary<string, string> v4)
        {
            foreach (var row in rows)
            {
                string? mac = InfrastructureFacts.MacFromBytes(row.Raw);
                if (!InfrastructureFacts.IsUsableMac(mac) || !TryParseIpNetToMediaIndex(row.Oid, out IPAddress? ip) || ip == null) continue;
                v4[ip.ToString()] = mac!;
            }
        }

        internal static void ParseIntIndexedStrings(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows, string baseOid, Dictionary<int, string> target)
        {
            foreach (var row in rows)
            {
                long[]? s = OidUtil.Suffix(row.Oid, baseOid);
                if (s == null || s.Length != 1 || s[0] < 0 || s[0] > int.MaxValue) continue;
                string text = row.Text.Trim();
                if (text.Length > 0) target[(int)s[0]] = text;
            }
        }

        internal static void ParseBridgePortIfIndex(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows, Dictionary<int, int> target)
        {
            foreach (var row in rows)
            {
                long[]? s = OidUtil.Suffix(row.Oid, OidDot1dBasePortIfIndex);
                if (s == null || s.Length != 1 || s[0] < 0 || s[0] > int.MaxValue) continue;
                long ifIndex = SnmpBer.DecodeSigned(row.Raw);
                if (ifIndex > 0 && ifIndex <= int.MaxValue) target[(int)s[0]] = (int)ifIndex;
            }
        }

        internal static void ParseFdb(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows, string baseOid, bool vlanIndexed, Dictionary<string, int> macToPort)
        {
            foreach (var row in rows)
            {
                string? mac = ParseFdbIndexMac(row.Oid, baseOid, vlanIndexed);
                if (!InfrastructureFacts.IsUsableMac(mac)) continue;
                long port = SnmpBer.DecodeSigned(row.Raw);
                if (port <= 0 || port > int.MaxValue) continue; // 0 = 포트 미상(self 등)
                if (!macToPort.ContainsKey(mac!)) macToPort[mac!] = (int)port;
            }
        }

        // lldpRemTable 전체 걷기 결과를 (timeMark.localPortNum.remIndex) 단위로 묶어 이웃 목록을 만든다.
        internal static List<LldpNeighbor> AssembleLldp(IReadOnlyList<(string Oid, byte Type, byte[] Raw, string Text)> rows)
        {
            var byIndex = new Dictionary<string, LldpNeighbor>(StringComparer.Ordinal);
            var order = new List<string>();
            var chassisRaw = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var portRaw = new Dictionary<string, byte[]>(StringComparer.Ordinal);

            foreach (var row in rows)
            {
                long[]? s = OidUtil.Suffix(row.Oid, OidLldpRemTable);
                if (s == null || s.Length != 4) continue;
                int column = (int)s[0];
                string key = $"{s[1]}.{s[2]}.{s[3]}";
                if (!byIndex.TryGetValue(key, out LldpNeighbor? n))
                {
                    n = new LldpNeighbor { LocalPortNum = s[2] >= 0 && s[2] <= int.MaxValue ? (int)s[2] : 0 };
                    byIndex[key] = n;
                    order.Add(key);
                }
                switch (column)
                {
                    case LldpColChassisIdSubtype: n.ChassisIdSubtype = (int)SnmpBer.DecodeSigned(row.Raw); break;
                    case LldpColChassisId: chassisRaw[key] = row.Raw; break;
                    case LldpColPortIdSubtype: n.PortIdSubtype = (int)SnmpBer.DecodeSigned(row.Raw); break;
                    case LldpColPortId: portRaw[key] = row.Raw; break;
                    case LldpColPortDesc: n.PortDesc = row.Text; break;
                    case LldpColSysName: n.SysName = row.Text; break;
                    case LldpColSysDesc: n.SysDesc = row.Text; break;
                }
            }

            var list = new List<LldpNeighbor>(order.Count);
            foreach (string key in order)
            {
                LldpNeighbor n = byIndex[key];
                if (chassisRaw.TryGetValue(key, out byte[]? c))
                {
                    n.ChassisId = IdText(n.ChassisIdSubtype, c, macSubtype: 4, networkSubtype: 5);
                    if (n.ChassisIdSubtype == 4 || (n.ChassisIdSubtype == 0 && c.Length == 6 && !SnmpBer.IsPrintable(c)))
                        n.ChassisMac = InfrastructureFacts.MacFromBytes(c);
                }
                if (portRaw.TryGetValue(key, out byte[]? p))
                    n.PortId = IdText(n.PortIdSubtype, p, macSubtype: 3, networkSubtype: 4);
                list.Add(n);
            }
            return list;
        }

        // LLDP chassis/port ID: MAC 하위타입이면 MAC 표기, networkAddress면 IP, 그 외는 텍스트(바이너리면 hex).
        private static string IdText(int subtype, byte[] raw, int macSubtype, int networkSubtype)
        {
            if (subtype == macSubtype && raw.Length == 6) return InfrastructureFacts.MacFromBytes(raw) ?? SnmpBer.ToHex(raw);
            if (subtype == networkSubtype && raw.Length == 5 && raw[0] == 1) return $"{raw[1]}.{raw[2]}.{raw[3]}.{raw[4]}";
            if (subtype == networkSubtype && raw.Length == 17 && raw[0] == 2)
            {
                try { return new IPAddress(raw.AsSpan(1).ToArray()).ToString(); } catch { }
            }
            return SnmpBer.FormatText(SnmpBer.TagOctetString, raw);
        }

        // ---- 사실 조립 ----

        private sealed class PortCandidate
        {
            public string Label = "";
            public int MacsOnPort;
            public string Source = "";
        }

        internal static IReadOnlyDictionary<string, IReadOnlyList<Fact>> BuildFacts(IReadOnlyList<AgentTables> agents)
        {
            var result = new Dictionary<string, HostFacts>(StringComparer.Ordinal);
            HostFacts Of(string key)
            {
                if (!result.TryGetValue(key, out HostFacts? f)) { f = new HostFacts(key); result[key] = f; }
                return f;
            }

            // MAC → 포트 후보. 여러 장비가 같은 MAC을 알면 가장 적은 MAC을 가진 포트(업링크가 아닌 접속 포트)를 고른다.
            var candidates = new Dictionary<string, List<PortCandidate>>(StringComparer.Ordinal);
            foreach (AgentTables t in agents)
            {
                string source = $"{InfrastructureFacts.SourceSnmpTable}:{t.Agent}";
                var perPort = t.MacToBridgePort.GroupBy(kv => kv.Value).ToDictionary(g => g.Key, g => g.Count());
                foreach (var (mac, port) in t.MacToBridgePort)
                {
                    if (!candidates.TryGetValue(mac, out List<PortCandidate>? list)) { list = new List<PortCandidate>(); candidates[mac] = list; }
                    list.Add(new PortCandidate { Label = $"{t.Label} / {t.PortLabel(port)}", MacsOnPort = perPort[port], Source = source });
                }
            }
            var bestPort = new Dictionary<string, (string Label, Confidence Confidence, string Source)>(StringComparer.Ordinal);
            foreach (var (mac, list) in candidates)
            {
                PortCandidate best = list.OrderBy(c => c.MacsOnPort).First();
                // 포트에 MAC이 2개 이하면 접속 포트(High), 많으면 업링크/트렁크일 수 있어 Medium.
                bestPort[mac] = (best.Label, best.MacsOnPort <= 2 ? Confidence.High : Confidence.Medium, best.Source);
                Of(InfrastructureFacts.MacKey(mac)).Add(FactFields.SwitchPort, best.Label, best.Source, bestPort[mac].Confidence);
            }

            foreach (AgentTables t in agents)
            {
                string source = $"{InfrastructureFacts.SourceSnmpTable}:{t.Agent}";
                string seenBy = t.Agent.ToString();

                // IPv4 ARP
                var macToIpv4 = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var (ip, mac) in t.ArpV4)
                {
                    HostFacts f = Of(ip);
                    f.Add(FactFields.Mac, mac, source, Confidence.High);
                    f.Add(InfrastructureFacts.SeenByField, seenBy, source, Confidence.Medium);
                    if (bestPort.TryGetValue(mac, out var port)) f.Add(FactFields.SwitchPort, port.Label, port.Source, port.Confidence);
                    if (!macToIpv4.ContainsKey(mac)) macToIpv4[mac] = ip;
                }

                // IPv6 ARP(ND): 같은 MAC의 IPv4 호스트가 있으면 그쪽에 ipv6을 붙이고, 없으면 v6 전용 키로.
                foreach (var (ip6, mac) in t.ArpV6)
                {
                    if (macToIpv4.TryGetValue(mac, out string? ip4))
                    {
                        Of(ip4).Add(FactFields.Ipv6, ip6, source, Confidence.High);
                    }
                    else
                    {
                        HostFacts f = Of(InfrastructureFacts.V6Key(ip6));
                        f.Add(FactFields.Mac, mac, source, Confidence.High);
                        f.Add(InfrastructureFacts.SeenByField, seenBy, source, Confidence.Medium);
                    }
                }

                // LLDP 이웃
                foreach (LldpNeighbor n in t.Lldp)
                {
                    string ident = !string.IsNullOrWhiteSpace(n.SysName) ? n.SysName.Trim() : n.ChassisId;
                    if (string.IsNullOrWhiteSpace(ident)) continue;
                    string remotePort = !string.IsNullOrWhiteSpace(n.PortId) ? n.PortId : n.PortDesc;
                    string link = $"{t.Label}/{t.LocalPortLabel(n.LocalPortNum)} ↔ {(string.IsNullOrWhiteSpace(remotePort) ? "?" : remotePort)}";

                    HostFacts f = Of(InfrastructureFacts.LldpKey(ident));
                    f.Add(FactFields.Name, n.SysName, source, Confidence.High);
                    f.Add(FactFields.Description, n.SysDesc, source, Confidence.Medium);
                    f.Add(FactFields.SwitchPort, link, source, Confidence.High);
                    if (n.ChassisMac != null && InfrastructureFacts.IsUsableMac(n.ChassisMac))
                    {
                        f.Add(FactFields.Mac, n.ChassisMac, source, Confidence.High);
                        HostFacts byMac = Of(InfrastructureFacts.MacKey(n.ChassisMac));
                        byMac.Add(FactFields.SwitchPort, link, source, Confidence.High);
                        byMac.Add(FactFields.Name, n.SysName, source, Confidence.High);
                        byMac.Add(FactFields.Description, n.SysDesc, source, Confidence.Medium);
                        // 이 장비의 ARP에 chassis MAC이 있으면 IP 키에도 이름/포트를 붙여 준다.
                        if (macToIpv4.TryGetValue(n.ChassisMac, out string? ip4))
                        {
                            HostFacts h = Of(ip4);
                            h.Add(FactFields.Name, n.SysName, source, Confidence.High);
                            h.Add(FactFields.Description, n.SysDesc, source, Confidence.Medium);
                            h.Add(FactFields.SwitchPort, link, source, Confidence.High);
                        }
                    }
                }
            }

            return result.ToDictionary(kv => kv.Key, kv => kv.Value.All, StringComparer.Ordinal);
        }
    }
}
