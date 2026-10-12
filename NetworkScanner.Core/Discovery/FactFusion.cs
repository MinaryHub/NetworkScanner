using System;
using System.Collections.Generic;
using System.Linq;

namespace NetworkScanner.Discovery
{
    // 여러 출처의 사실을 한 호스트의 표시 값으로 합친다. 규칙은 단순하다: 필드마다 가장 확신 높은 값을 쓰고,
    // 동률이면 먼저 수집된(현재 스캔의) 값을 우선한다. 이전 스캔의 사실은 한 단계 낮은 신뢰도로 들어온다.
    public static class FactFusion
    {
        public const string SourceArp = "ARP";
        public const string SourceOui = "OUI";
        public const string SourceDns = "DNS";
        public const string SourceTtl = "TTL";
        public const string SourceBanner = "banner";
        public const string SourceHistory = "history";

        // 현재 스캔에 없는 필드만 이전 사실로 채운다(신뢰도 한 단계 하향, 출처에 "history:" 접두어).
        public static void MergeHistory(HostFacts current, HostFacts previous)
        {
            foreach (string field in previous.All.Select(f => f.Field).Distinct())
            {
                if (current.Of(field).Any()) continue;
                Fact? best = previous.Best(field);
                if (best == null) continue;
                Confidence lowered = best.Confidence == Confidence.High ? Confidence.Medium : Confidence.Low;
                string source = best.Source.StartsWith(SourceHistory, StringComparison.Ordinal) ? best.Source : SourceHistory + ":" + best.Source;
                current.Add(field, best.Value, source, lowered);
            }
        }

        // 프로브들이 쓰는 범주 토큰 → 지역화된 종류 문자열. 모르는 토큰은 그대로 보여준다.
        public static string DeviceCategoryLabel(string token)
        {
            string key = token.Trim().ToLowerInvariant() switch
            {
                "router" or "network" or "switch" or "ap" or "accesspoint" or "gateway" or "internetgatewaydevice" or "wlan" => "dev.network",
                "computer" or "pc" or "desktop" or "laptop" or "workstation" => "dev.pclaptop",
                "server" => "dev.server",
                "nas" or "storage" => "dev.nas",
                "printer" or "scanner" or "mfp" => "dev.printer",
                "media" or "tv" or "console" or "roku" or "mediarenderer" or "mediaserver" or "speaker" or "cast" => "dev.media",
                "phone" or "tablet" or "mobile" => "dev.mobile",
                "ipphone" or "voip" => "dev.voip",
                "camera" or "ipcam" => "dev.cctv",
                "iot" or "embedded" or "sensor" or "appliance" => "dev.iot",
                _ => "",
            };
            return key.Length == 0 ? token : Localization.T(key);
        }

        // 사실 → IPInfo 표시 필드. 이미 더 확실한 값이 있는 필드는 덮어쓰지 않는다(ARP MAC, OUI 제조사 등).
        public static void ApplyTo(HostFacts facts, IPInfo info, Func<string, string> vendorFromMac)
        {
            string name = facts.BestValue(FactFields.Name);
            if (!string.IsNullOrEmpty(name) && (string.IsNullOrEmpty(info.SystemName) || BetterThan(facts.Best(FactFields.Name), Confidence.Medium)))
                info.SystemName = name;

            // OS: TTL만으로 추정한 Low 사실은 힌트로 쓰지 않는다(호스트명/포트 휴리스틱이 더 정확).
            Fact? osFact = facts.Best(FactFields.Os);
            if (osFact != null && osFact.Confidence >= Confidence.Medium && !string.IsNullOrEmpty(osFact.Value)) info.OsHint = osFact.Value;
            info.OsVersion = Prefer(info.OsVersion, facts.BestValue(FactFields.OsVersion));
            info.Model = Prefer(info.Model, facts.BestValue(FactFields.Model));
            info.SwitchPort = Prefer(info.SwitchPort, facts.BestValue(FactFields.SwitchPort));
            info.Ipv6 = Prefer(info.Ipv6, facts.BestValue(FactFields.Ipv6));

            // 종류: 프로브가 준 범주 토큰(router/nas/printer…)을 표시 문자열로 바꾼다. 모델은 별도 열(Model).
            string deviceType = facts.BestValue(FactFields.DeviceType);
            if (!string.IsNullOrEmpty(deviceType)) info.DeviceHint = DeviceCategoryLabel(deviceType);

            string mac = facts.BestValue(FactFields.Mac);
            if (string.IsNullOrEmpty(info.Macaddr) && !string.IsNullOrEmpty(mac))
            {
                info.Macaddr = mac;
                info.Vendor = vendorFromMac(mac);
            }

            // 제조사: OUI가 비었거나 "랜덤 MAC" 표시뿐이면 SSDP/mDNS/HTTP가 알려준 제조사를 쓴다.
            string vendor = facts.BestValue(FactFields.Vendor);
            if (!string.IsNullOrEmpty(vendor) && (string.IsNullOrEmpty(info.Vendor) || info.Vendor == Localization.T("vendor.private")))
                info.Vendor = vendor;

            string service = facts.BestValue(FactFields.Service);
            if (string.IsNullOrEmpty(info.Service) && !string.IsNullOrEmpty(service)) info.Service = service;

            // 설명: 프로브가 확인한(High) 값은 재스캔 때 갱신하고, SSDP 위치 같은 낮은 확신 값은 빈 칸만 채운다.
            Fact? descFact = facts.Best(FactFields.Description);
            if (descFact != null && !string.IsNullOrEmpty(descFact.Value) && (string.IsNullOrEmpty(info.SysDescr) || BetterThan(descFact, Confidence.Medium)))
                info.SysDescr = descFact.Value;

            info.FactsJson = facts.ToJson();
        }

        private static bool BetterThan(Fact? f, Confidence threshold) => f != null && f.Confidence > threshold;
        private static string Prefer(string current, string candidate) => string.IsNullOrEmpty(candidate) ? current : candidate;

        // 1단계 ICMP 응답시간(ms)의 p95로 재시도/포트 타임아웃을 늘린다. 응답이 적으면 기본값 유지.
        public static int AdaptiveTimeout(IReadOnlyList<long> rttMs, int baseTimeoutMs, int multiplier, int maxMs)
        {
            if (rttMs.Count < 3) return baseTimeoutMs;
            var sorted = rttMs.OrderBy(x => x).ToList();
            long p95 = sorted[Math.Min(sorted.Count - 1, (int)Math.Ceiling(sorted.Count * 0.95) - 1)];
            long candidate = Math.Max(p95, 1) * multiplier;
            return (int)Math.Clamp(candidate, baseTimeoutMs, maxMs);
        }

        // "ip[:community]; ip2" 형식의 SNMP 장비 목록.
        public static List<(System.Net.IPAddress Ip, string Community)> ParseSnmpAgents(string? text, string defaultCommunity)
        {
            var list = new List<(System.Net.IPAddress, string)>();
            if (string.IsNullOrWhiteSpace(text)) return list;
            foreach (string token in text.Split(new[] { ';', ',', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = token.Split(':', 2);
                if (System.Net.IPAddress.TryParse(parts[0].Trim(), out var ip))
                    list.Add((ip, parts.Length > 1 && parts[1].Trim().Length > 0 ? parts[1].Trim() : defaultCommunity));
            }
            return list;
        }
    }
}
