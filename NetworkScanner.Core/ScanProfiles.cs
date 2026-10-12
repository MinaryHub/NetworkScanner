using System;
using System.Collections.Generic;

namespace NetworkScanner
{
    // 스캔 프로필: 같은 설정 파일 안에서 "빠르게 훑기 / 표준 / 정밀"을 바꿔 쓴다.
    // 프로필은 ScanOptions의 동시성·타임아웃·식별·평가 범위만 바꾸고, 대역·포트 목록·업로드 설정은 건드리지 않는다.
    public enum ScanProfileKind { Standard, Quick, Thorough }

    public static class ScanProfiles
    {
        public static ScanProfileKind Parse(string? name) => (name ?? "").Trim().ToLowerInvariant() switch
        {
            "quick" or "fast" or "빠름" => ScanProfileKind.Quick,
            "thorough" or "full" or "deep" or "정밀" => ScanProfileKind.Thorough,
            _ => ScanProfileKind.Standard,
        };

        public static string Name(ScanProfileKind kind) => kind switch
        {
            ScanProfileKind.Quick => "quick",
            ScanProfileKind.Thorough => "thorough",
            _ => "standard",
        };

        public static string DisplayName(ScanProfileKind kind) => Localization.T("profile." + Name(kind));

        public static IReadOnlyList<ScanProfileKind> All { get; } = new[] { ScanProfileKind.Quick, ScanProfileKind.Standard, ScanProfileKind.Thorough };

        // 프로필을 옵션에 적용한다. 세 프로필은 서로 같은 필드 집합을 모두 설정하므로, 같은 옵션 객체에
        // 다른 프로필을 연달아 적용해도 이전 프로필의 값이 남지 않는다. Standard는 ScanOptions 기본값을 되돌린다
        // (식별/평가 사용 여부는 설정값이므로 Standard에서는 건드리지 않는다).
        public static ScanOptions Apply(ScanOptions options, ScanProfileKind kind)
        {
            var defaults = new ScanOptions();
            switch (kind)
            {
                case ScanProfileKind.Quick:
                    options.Parallelism = Math.Max(options.Parallelism, 128);
                    options.PingTimeoutMs = 300;
                    options.TcpLivenessTimeoutMs = 300;
                    options.PortTimeoutMs = 200;
                    options.BannerTimeoutMs = defaults.BannerTimeoutMs;
                    options.DnsTimeoutMs = 500;
                    options.IdentityProbes = false;
                    options.BannerGrab = false;
                    options.AssessVulnerabilities = false;
                    options.DeepDiscovery = false;
                    options.ExtraPorts = Array.Empty<int>();
                    break;
                case ScanProfileKind.Thorough:
                    options.Parallelism = Math.Min(options.Parallelism, 32);
                    options.PingTimeoutMs = 1000;
                    options.TcpLivenessTimeoutMs = 800;
                    options.PortTimeoutMs = 600;
                    options.BannerTimeoutMs = 1200;
                    options.DnsTimeoutMs = 2500;
                    options.IdentityProbes = true;
                    options.BannerGrab = true;
                    options.AssessVulnerabilities = true;
                    options.DeepDiscovery = true;
                    options.ExtraPorts = TopPorts;
                    break;
                default:
                    options.PingTimeoutMs = defaults.PingTimeoutMs;
                    options.TcpLivenessTimeoutMs = defaults.TcpLivenessTimeoutMs;
                    options.PortTimeoutMs = defaults.PortTimeoutMs;
                    options.BannerTimeoutMs = defaults.BannerTimeoutMs;
                    options.DnsTimeoutMs = defaults.DnsTimeoutMs;
                    options.BannerGrab = defaults.BannerGrab;
                    options.DeepDiscovery = defaults.DeepDiscovery;
                    options.ExtraPorts = Array.Empty<int>();
                    break;
            }
            options.Profile = kind;
            return options;
        }

        // 정밀 프로필에서 사용자 포트 목록에 더해 검사하는 대표 포트(서비스 식별·취약점 평가에 유용한 것 위주).
        public static readonly int[] TopPorts =
        {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 515, 548, 587, 631, 636, 873, 902, 993, 995,
            1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4443, 4786, 5000, 5060,
            5432, 5555, 5601, 5900, 5985, 5986, 6379, 6443, 7001, 7547, 8000, 8008, 8080, 8081, 8088, 8291, 8443, 8888, 9000, 9090,
            9100, 9200, 9300, 10000, 27017, 50000,
        };
    }
}
