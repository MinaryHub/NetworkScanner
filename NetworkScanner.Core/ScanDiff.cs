using System;
using System.Collections.Generic;
using NetworkScanner.History;

namespace NetworkScanner
{
    public enum ScanChangeType
    {
        NewHost,            // 새로 나타났거나 다시 접속된 호스트
        HostOffline,        // 이전엔 살아있었으나 이번엔 응답 없음
        MacChanged,         // 같은 IP인데 MAC이 바뀜(ARP 스푸핑/비인가 장비 의심)
        NewOpenPort,        // 이전에 없던 포트가 새로 열림
        ProhibitedPort,     // 위험(백도어) 포트가 열려 있음
        UnapprovedHost,     // 승인 목록에 없는 장비가 살아있음(자산 승인 정책 사용 시)
        ApprovedMacMismatch,// 승인된 IP의 MAC이 승인 당시와 다름(IP 도용/장비 교체 의심)
        HighRisk,           // 취약점 평가 점수가 기준 이상
    }

    // 한 호스트의 스캔 상태 스냅샷. 두 스캔 사이의 변화를 계산하는 데 쓰인다.
    public sealed record HostState(bool Alive, string Mac, string Ports, bool HasProhibited, int RiskScore = 0);

    public sealed record ScanChange(ScanChangeType Type, string Ip, string Detail);

    // 자산 승인 정책. Enabled면 승인되지 않은 살아있는 호스트를 UnapprovedHost로 보고한다.
    public sealed record AssetPolicy(bool AlertOnUnapproved, int HighRiskThreshold = 40)
    {
        public static AssetPolicy Disabled { get; } = new(false);
    }

    // 직전 스캔(baseline)과 이번 스캔(current)을 비교해 의미 있는 변화를 뽑아낸다.
    // 네트워크에 의존하지 않는 순수 로직이라 단위 테스트로 검증한다.
    public static class ScanDiff
    {
        public static List<ScanChange> ComputeChanges(
            IReadOnlyDictionary<string, HostState> baseline,
            IReadOnlyDictionary<string, HostState> current)
            => ComputeChanges(baseline, current, null, AssetPolicy.Disabled);

        public static List<ScanChange> ComputeChanges(
            IReadOnlyDictionary<string, HostState> baseline,
            IReadOnlyDictionary<string, HostState> current,
            IReadOnlyDictionary<string, ApprovedHost>? approved,
            AssetPolicy policy)
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

                if (cur.Alive && policy.HighRiskThreshold > 0 && cur.RiskScore >= policy.HighRiskThreshold)
                    changes.Add(new ScanChange(ScanChangeType.HighRisk, ip, cur.RiskScore.ToString()));

                // 자산 승인 정책: 승인되지 않은 장비, 승인 MAC과 다른 장비.
                if (cur.Alive && approved != null)
                {
                    if (!approved.TryGetValue(ip, out ApprovedHost? ok))
                    {
                        if (policy.AlertOnUnapproved) changes.Add(new ScanChange(ScanChangeType.UnapprovedHost, ip, cur.Mac));
                    }
                    else if (!string.IsNullOrEmpty(ok.ApprovedMac) && !string.IsNullOrEmpty(cur.Mac)
                             && !string.Equals(ok.ApprovedMac, cur.Mac, StringComparison.OrdinalIgnoreCase))
                    {
                        changes.Add(new ScanChange(ScanChangeType.ApprovedMacMismatch, ip, $"{ok.ApprovedMac} → {cur.Mac}"));
                    }
                }
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
            ScanChangeType.UnapprovedHost => $"{Localization.T("change.unapproved")} {c.Ip}  {c.Detail}",
            ScanChangeType.ApprovedMacMismatch => $"{Localization.T("change.approvedmac")} {c.Ip}  {c.Detail}",
            ScanChangeType.HighRisk => $"{Localization.T("change.highrisk")} {c.Ip}  ({c.Detail})",
            _ => $"{c.Ip} {c.Detail}",
        };

        // MAC 변경/위험 포트/미승인 장비/고위험은 보안상 사용자에게 적극적으로 경고해야 하는 항목이다.
        public static bool IsSecurityRelevant(ScanChangeType type)
            => type is ScanChangeType.MacChanged or ScanChangeType.ProhibitedPort
                or ScanChangeType.UnapprovedHost or ScanChangeType.ApprovedMacMismatch or ScanChangeType.HighRisk;

        // 알림 중복 억제용 키. 같은 사건은 스캔마다 반복돼도 한 알림으로 누적된다.
        public static string AlertKey(ScanChange c) => c.Type switch
        {
            ScanChangeType.NewOpenPort => $"{c.Type}|{c.Ip}|{c.Detail}",
            ScanChangeType.MacChanged => $"{c.Type}|{c.Ip}|{c.Detail}",
            ScanChangeType.ApprovedMacMismatch => $"{c.Type}|{c.Ip}|{c.Detail}",
            _ => $"{c.Type}|{c.Ip}",
        };

        // 상태형 알림: 조건이 사라지면(이번 스캔에서 관찰되지 않으면) 자동으로 해결 처리할 수 있는 종류.
        public static readonly ScanChangeType[] ResolvableTypes =
        {
            ScanChangeType.ProhibitedPort, ScanChangeType.UnapprovedHost, ScanChangeType.ApprovedMacMismatch, ScanChangeType.HighRisk,
        };

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
