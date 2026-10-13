using System;
using System.Collections.Generic;
using System.Linq;
using KetworkScanner.Discovery;

namespace KetworkScanner.Capture
{
    // PassiveListener가 쏟아내는 관찰을 IP별·MAC별로 모아 두는 스레드 안전 저장소.
    // 같은 키·같은 Source는 최신 관찰 하나만 유지한다. 엔진은 스캔이 끝날 때마다 Snapshot()으로 합치고, 서비스는 리스너를 계속 돌린다.
    public sealed class ObservationAggregator
    {
        private sealed class Entry
        {
            public readonly Dictionary<string, HostObservation> LatestBySource = new(StringComparer.Ordinal);
            public DateTimeOffset LastSeen;
            public string Mac = "";   // IP 항목: 마지막으로 본 MAC
            public string Ip = "";    // MAC 항목: 마지막으로 본 IP
        }

        private readonly object _lock = new();
        private readonly Dictionary<string, Entry> _byIp = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Entry> _byMac = new(StringComparer.OrdinalIgnoreCase);
        private long _total;

        // 지금까지 Add()된 관찰 수(프루닝과 무관한 누계).
        public long ObservationCount => Interlocked.Read(ref _total);
        public int IpCount { get { lock (_lock) return _byIp.Count; } }
        public int MacCount { get { lock (_lock) return _byMac.Count; } }

        public void Add(HostObservation obs)
        {
            if (obs == null) return;
            if (!obs.HasIp && !obs.HasMac) return;
            Interlocked.Increment(ref _total);
            lock (_lock)
            {
                if (obs.HasIp)
                {
                    Entry e = GetOrAdd(_byIp, obs.Ip);
                    Put(e, obs);
                    if (obs.HasMac) e.Mac = obs.Mac;
                }
                if (obs.HasMac)
                {
                    Entry e = GetOrAdd(_byMac, obs.Mac);
                    Put(e, obs);
                    if (obs.HasIp) e.Ip = obs.Ip;
                }
            }
        }

        public DateTimeOffset? LastSeenByIp(string ip)
        {
            lock (_lock) return _byIp.TryGetValue(ip, out Entry? e) ? e.LastSeen : null;
        }

        // IP가 알려진 MAC의 최신 IP(DHCP DISCOVER처럼 IP 없이 온 관찰을 엔진이 합칠 때 사용).
        public string? IpOfMac(string mac)
        {
            lock (_lock) return _byMac.TryGetValue(mac, out Entry? e) && e.Ip.Length > 0 ? e.Ip : null;
        }

        public (IReadOnlyDictionary<string, HostFacts> ByIp, IReadOnlyDictionary<string, HostFacts> ByMac) Snapshot()
        {
            lock (_lock)
            {
                var byIp = new Dictionary<string, HostFacts>(StringComparer.Ordinal);
                foreach (var (ip, e) in _byIp)
                {
                    var facts = new HostFacts(ip);
                    Fold(facts, e);
                    // 같은 MAC으로 들어온, IP 없는 관찰(DHCP DISCOVER 등)도 끌어온다.
                    if (e.Mac.Length > 0 && _byMac.TryGetValue(e.Mac, out Entry? m)) Fold(facts, m);
                    byIp[ip] = facts;
                }
                var byMac = new Dictionary<string, HostFacts>(StringComparer.OrdinalIgnoreCase);
                foreach (var (mac, e) in _byMac)
                {
                    var facts = new HostFacts(e.Ip);
                    Fold(facts, e);
                    byMac[mac] = facts;
                }
                return (byIp, byMac);
            }
        }

        public IReadOnlyDictionary<string, HostFacts> SnapshotByIp() => Snapshot().ByIp;

        // maxAge보다 오래 조용한 호스트 항목을 버린다. 지운 항목 수를 돌려준다.
        public int Prune(TimeSpan maxAge) => Prune(maxAge, DateTimeOffset.UtcNow);

        public int Prune(TimeSpan maxAge, DateTimeOffset now)
        {
            DateTimeOffset cutoff = now - maxAge;
            int removed = 0;
            lock (_lock)
            {
                removed += PruneDict(_byIp, cutoff);
                removed += PruneDict(_byMac, cutoff);
            }
            return removed;
        }

        public void Clear()
        {
            lock (_lock) { _byIp.Clear(); _byMac.Clear(); }
        }

        private static Entry GetOrAdd(Dictionary<string, Entry> dict, string key)
        {
            if (!dict.TryGetValue(key, out Entry? e)) { e = new Entry(); dict[key] = e; }
            return e;
        }

        private static void Put(Entry e, HostObservation obs)
        {
            // 같은 출처의 더 오래된 관찰이 늦게 도착해도 최신 것을 지킨다.
            if (e.LatestBySource.TryGetValue(obs.Source, out HostObservation? old) && old.At > obs.At) return;
            e.LatestBySource[obs.Source] = obs;
            if (obs.At > e.LastSeen) e.LastSeen = obs.At;
        }

        // 최신 관찰부터 넣어 같은 확신도면 최신 값이 Best()가 되게 한다.
        private static void Fold(HostFacts facts, Entry e)
        {
            foreach (HostObservation obs in e.LatestBySource.Values.OrderByDescending(o => o.At))
            {
                facts.AddRange(obs.Facts);
                if (obs.HasMac) facts.Add(FactFields.Mac, obs.Mac, obs.Source, Confidence.High);
            }
        }

        private static int PruneDict(Dictionary<string, Entry> dict, DateTimeOffset cutoff)
        {
            var dead = dict.Where(kv => kv.Value.LastSeen < cutoff).Select(kv => kv.Key).ToList();
            foreach (string k in dead) dict.Remove(k);
            return dead.Count;
        }
    }
}
