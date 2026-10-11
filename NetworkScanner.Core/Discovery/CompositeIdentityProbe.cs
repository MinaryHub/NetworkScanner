using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery
{
    // 여러 프로브를 같은 타임아웃으로 동시에 돌리고, 결과를 우선순위(기본: NetBIOS, mDNS, SNMP)로 정렬해 돌려준다.
    // ProbeAsync는 그 결과를 HostIdentityMerge.Merge로 합친 하나의 HostIdentity를 반환한다.
    public sealed class CompositeIdentityProbe : IIdentityProbe
    {
        public static readonly IReadOnlyList<string> DefaultPriority =
            new[] { HostIdentity.SourceNetBios, HostIdentity.SourceMdns, HostIdentity.SourceSnmp };

        private readonly IReadOnlyList<IIdentityProbe> _probes;

        public CompositeIdentityProbe(IEnumerable<IIdentityProbe> probes, IReadOnlyList<string>? priority = null)
        {
            _probes = probes.ToArray();
            Priority = priority ?? DefaultPriority;
        }

        // 기본 구성: NetBIOS + mDNS + SNMP(community 지정 가능)
        public static CompositeIdentityProbe CreateDefault(string snmpCommunity = "public")
            => new(new IIdentityProbe[] { new NetBiosProbe(), new MdnsProbe(), new SnmpProbe(snmpCommunity) });

        public string Name => "Composite";

        public IReadOnlyList<string> Priority { get; }

        public IReadOnlyList<IIdentityProbe> Probes => _probes;

        // 응답한 프로브의 결과만, 우선순위 순으로.
        public async Task<IReadOnlyList<HostIdentity>> ProbeAllAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            if (_probes.Count == 0) return Array.Empty<HostIdentity>();
            var tasks = _probes.Select(p => RunSafe(p, ip, timeoutMs, ct)).ToArray();
            HostIdentity?[] results;
            try
            {
                results = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch
            {
                return Array.Empty<HostIdentity>();
            }
            return results.Where(r => r != null).Select(r => r!)
                .OrderBy(r => HostIdentityMerge.Rank(r.Source, Priority)).ToArray();
        }

        public async Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                return HostIdentityMerge.Merge(await ProbeAllAsync(ip, timeoutMs, ct).ConfigureAwait(false), Priority);
            }
            catch
            {
                return null;
            }
        }

        private static async Task<HostIdentity?> RunSafe(IIdentityProbe probe, IPAddress ip, int timeoutMs, CancellationToken ct)
        {
            try
            {
                return await probe.ProbeAsync(ip, timeoutMs, ct).ConfigureAwait(false);
            }
            catch
            {
                return null;
            }
        }
    }

    // 프로브 결과 병합 규칙과 표시 이름 선택 규칙.
    public static class HostIdentityMerge
    {
        public static int Rank(string source, IReadOnlyList<string>? priority = null)
        {
            priority ??= CompositeIdentityProbe.DefaultPriority;
            for (int i = 0; i < priority.Count; i++)
                if (string.Equals(priority[i], source, StringComparison.OrdinalIgnoreCase)) return i;
            return priority.Count;
        }

        // Name: 우선순위상 첫 비어있지 않은 이름. Description: SNMP sysDescr가 있으면 그것, 없으면 첫 설명.
        // OsHint/DeviceHint: 첫 non-null. Attributes: 합집합(먼저 온 값 유지). 결과가 없으면 null.
        public static HostIdentity? Merge(IEnumerable<HostIdentity> identities, IReadOnlyList<string>? priority = null)
        {
            var ordered = identities.Where(i => i != null).OrderBy(i => Rank(i.Source, priority)).ToList();
            if (ordered.Count == 0) return null;
            if (ordered.Count == 1) return ordered[0];

            string? name = ordered.Select(i => i.Name).FirstOrDefault(n => !string.IsNullOrWhiteSpace(n));
            HostIdentity? snmp = ordered.FirstOrDefault(i => i.Source == HostIdentity.SourceSnmp && !string.IsNullOrWhiteSpace(i.Description));
            string? description = snmp?.Description
                ?? ordered.Select(i => i.Description).FirstOrDefault(d => !string.IsNullOrWhiteSpace(d));
            string? os = ordered.Select(i => i.OsHint).FirstOrDefault(o => !string.IsNullOrWhiteSpace(o));
            string? device = ordered.Select(i => i.DeviceHint).FirstOrDefault(d => !string.IsNullOrWhiteSpace(d));

            var attrs = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var i in ordered)
                foreach (var kv in i.Attributes)
                    attrs.TryAdd(kv.Key, kv.Value);

            string source = string.Join("+", ordered.Select(i => i.Source).Distinct());
            return new HostIdentity(source, name, description, os, device, attrs);
        }

        // 표시 이름: 역방향 DNS 이름이 IP 문자열이 아니면 그것, 아니면 NetBIOS → mDNS → SNMP sysName → 병합 Name 순.
        public static string? ChooseName(string? dnsName, HostIdentity? merged)
        {
            string? dns = dnsName?.Trim();
            if (!string.IsNullOrEmpty(dns) && !IPAddress.TryParse(dns, out _)) return dns;
            if (merged == null) return null;

            foreach (string key in new[] { HostIdentity.AttrNetBiosName, HostIdentity.AttrMdnsName, HostIdentity.AttrSnmpSysName })
            {
                if (merged.Attributes.TryGetValue(key, out string? v) && !string.IsNullOrWhiteSpace(v)) return v;
            }
            return string.IsNullOrWhiteSpace(merged.Name) ? null : merged.Name;
        }
    }
}
