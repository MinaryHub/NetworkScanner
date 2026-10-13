using System;
using System.Collections.Generic;
using System.Net;

namespace KetworkScanner
{
    // 위험(백도어) 포트 판정 정책. 금지 포트 목록에 더해, 운영자가 승인한 예외(allow list)를 적용해
    // 알려진 정상 서비스(예: 사내 서버의 8080)가 매번 경고로 뜨는 알림 피로를 막는다.
    // 예외 항목 형식: "포트"(모든 호스트), "IP:포트"(특정 호스트), "IP"(그 호스트의 모든 포트), "CIDR:포트".
    public sealed class RiskPolicy
    {
        private readonly HashSet<int> _prohibited;
        private readonly HashSet<int> _globalAllow = new();
        private readonly Dictionary<string, HashSet<int>?> _hostAllow = new(); // null 값 = 모든 포트 허용
        private readonly List<(uint Network, uint Mask, int Port)> _cidrAllow = new();

        public RiskPolicy(IEnumerable<int> prohibitedPorts, IEnumerable<string>? allowList = null)
        {
            _prohibited = new HashSet<int>(prohibitedPorts);
            if (allowList != null)
                foreach (string entry in allowList) AddAllow(entry);
        }

        public static RiskPolicy Empty { get; } = new(Array.Empty<int>());

        private bool AddAllow(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return false;
            string entry = raw.Trim();

            if (int.TryParse(entry, out int onlyPort))
            {
                if (onlyPort is < 1 or > 65535) return false;
                _globalAllow.Add(onlyPort);
                return true;
            }

            int colon = entry.LastIndexOf(':');
            string hostPart = colon >= 0 ? entry.Substring(0, colon) : entry;
            int? port = null;
            if (colon >= 0)
            {
                if (!int.TryParse(entry.AsSpan(colon + 1), out int p) || p is < 1 or > 65535) return false;
                port = p;
            }

            if (hostPart.Contains('/'))
            {
                if (port == null) return false;
                string[] parts = hostPart.Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? net) || !int.TryParse(parts[1], out int prefix) || prefix is < 0 or > 32)
                    return false;
                uint mask = prefix == 0 ? 0u : 0xFFFFFFFF << (32 - prefix);
                _cidrAllow.Add((IPRangeUtil.ToUInt32(net) & mask, mask, port.Value));
                return true;
            }

            if (!IPAddress.TryParse(hostPart, out IPAddress? ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;
            string key = ip.ToString();
            if (port == null)
            {
                _hostAllow[key] = null;
                return true;
            }
            if (!_hostAllow.TryGetValue(key, out HashSet<int>? set))
            {
                set = new HashSet<int>();
                _hostAllow[key] = set;
            }
            set?.Add(port.Value);
            return true;
        }

        // 이 호스트의 이 포트가 "위험"으로 보고되어야 하는가.
        public bool IsRisky(string ip, int port)
        {
            if (!_prohibited.Contains(port)) return false;
            if (_globalAllow.Contains(port)) return false;
            if (_hostAllow.TryGetValue(ip, out HashSet<int>? set) && (set == null || set.Contains(port))) return false;
            if (_cidrAllow.Count > 0 && IPAddress.TryParse(ip, out IPAddress? addr))
            {
                uint v = IPRangeUtil.ToUInt32(addr);
                foreach (var (network, mask, p) in _cidrAllow)
                    if (p == port && (v & mask) == network) return false;
            }
            return true;
        }

        public bool HasRiskyPort(string ip, IEnumerable<int> openPorts)
        {
            foreach (int port in openPorts)
                if (IsRisky(ip, port)) return true;
            return false;
        }

        // 설정 문자열("8080, 10.0.0.5:31337; 10.0.1.0/24:12345") → 항목 목록. 잘못된 항목은 invalid로 돌려준다.
        public static (List<string> Valid, List<string> Invalid) ParseAllowList(string? text)
        {
            var valid = new List<string>();
            var invalid = new List<string>();
            if (string.IsNullOrWhiteSpace(text)) return (valid, invalid);
            var probe = new RiskPolicy(Array.Empty<int>());
            foreach (string token in text.Split(new[] { ',', ';', '\n', '\r', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (probe.AddAllow(token)) valid.Add(token.Trim()); else invalid.Add(token.Trim());
            }
            return (valid, invalid);
        }
    }
}
