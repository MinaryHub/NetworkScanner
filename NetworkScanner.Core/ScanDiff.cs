using System;
using System.Collections.Generic;

namespace NetworkScanner
{
    public enum ScanChangeType
    {
        NewHost,        // 새로 나타났거나 다시 접속된 호스트
        HostOffline,    // 이전엔 살아있었으나 이번엔 응답 없음
        MacChanged,     // 같은 IP인데 MAC이 바뀜(ARP 스푸핑/비인가 장비 의심)
        NewOpenPort,    // 이전에 없던 포트가 새로 열림
        ProhibitedPort, // 위험(백도어) 포트가 열려 있음
    }

    // 한 호스트의 스캔 상태 스냅샷. 두 스캔 사이의 변화를 계산하는 데 쓰인다.
    public sealed record HostState(bool Alive, string Mac, string Ports, bool HasProhibited);

    public sealed record ScanChange(ScanChangeType Type, string Ip, string Detail);

    // 직전 스캔(baseline)과 이번 스캔(current)을 비교해 의미 있는 변화를 뽑아낸다.
    // 네트워크에 의존하지 않는 순수 로직이라 단위 테스트로 검증한다.
    public static class ScanDiff
    {
        public static List<ScanChange> ComputeChanges(
            IReadOnlyDictionary<string, HostState> baseline,
            IReadOnlyDictionary<string, HostState> current)
        {
            var changes = new List<ScanChange>();
            bool firstScan = baseline.Count == 0; // 최초 스캔이면 모든 것이 "새것"이라 신규/포트 변화는 보고하지 않는다.

            foreach (var kv in current)
            {
                string ip = kv.Key;
                HostState cur = kv.Value;
                baseline.TryGetValue(ip, out HostState? prev);
                bool wasAlive = prev is { Alive: true };

                if (cur.Alive && !wasAlive && !firstScan)
                    changes.Add(new ScanChange(ScanChangeType.NewHost, ip, prev == null ? Localization.T("change.newdevice") : Localization.T("change.reconnect")));

                if (!cur.Alive && wasAlive)
                    changes.Add(new ScanChange(ScanChangeType.HostOffline, ip, Localization.T("change.noresponse")));

                if (prev != null
                    && !string.IsNullOrEmpty(prev.Mac) && !string.IsNullOrEmpty(cur.Mac)
                    && !string.Equals(prev.Mac, cur.Mac, StringComparison.OrdinalIgnoreCase))
                    changes.Add(new ScanChange(ScanChangeType.MacChanged, ip, $"{prev.Mac} → {cur.Mac}"));

                // 새 포트는 이전에 알던 호스트에 대해서만 의미가 있다(새 호스트는 NewHost로 이미 알림).
                if (prev != null && !firstScan)
                {
                    HashSet<int> before = ParsePorts(prev.Ports);
                    foreach (int port in ParsePorts(cur.Ports))
                        if (!before.Contains(port))
                            changes.Add(new ScanChange(ScanChangeType.NewOpenPort, ip, port.ToString()));
                }

                if (cur.HasProhibited)
                    changes.Add(new ScanChange(ScanChangeType.ProhibitedPort, ip, cur.Ports));
            }

            // 기준선에는 살아있었는데 이번 결과에 아예 없는 호스트(재시작 후 이력 DB를 기준선으로 쓴 경우 등)도 오프라인으로 본다.
            foreach (var kv in baseline)
            {
                if (kv.Value.Alive && !current.ContainsKey(kv.Key))
                    changes.Add(new ScanChange(ScanChangeType.HostOffline, kv.Key, Localization.T("change.noresponse")));
            }

            return changes;
        }

        // 사용자에게 보여줄 한 줄 설명.
        public static string Describe(ScanChange c) => c.Type switch
        {
            ScanChangeType.NewHost => $"{Localization.T("change.newhost")} {c.Ip} ({c.Detail})",
            ScanChangeType.HostOffline => $"{Localization.T("change.offline")} {c.Ip}",
            ScanChangeType.MacChanged => $"{Localization.T("change.macchanged")} {c.Ip}  {c.Detail}",
            ScanChangeType.NewOpenPort => $"{Localization.T("change.newport")} {c.Ip}  :{c.Detail}",
            ScanChangeType.ProhibitedPort => $"{Localization.T("change.prohibited")} {c.Ip}  ({c.Detail})",
            _ => $"{c.Ip} {c.Detail}",
        };

        // MAC 변경/위험 포트는 보안상 사용자에게 적극적으로 경고해야 하는 항목이다.
        public static bool IsSecurityRelevant(ScanChangeType type)
            => type is ScanChangeType.MacChanged or ScanChangeType.ProhibitedPort;

        private static HashSet<int> ParsePorts(string? field)
        {
            var set = new HashSet<int>();
            if (string.IsNullOrEmpty(field)) return set;
            foreach (string token in field.Split('/', StringSplitOptions.RemoveEmptyEntries))
                if (int.TryParse(token, out int port))
                    set.Add(port);
            return set;
        }
    }
}
