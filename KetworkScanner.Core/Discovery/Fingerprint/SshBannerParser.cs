using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace KetworkScanner.Discovery.Fingerprint
{
    // SSH 식별 문자열(RFC 4253 4.2) "SSH-2.0-<software> [comments]" 해석. 소프트웨어 토큰은 service로, 배포판 꼬리표
    // (Ubuntu-/Debian-/Raspbian-/FreeBSD-…)와 제품명(dropbear/Cisco/ROSSSH…)은 os/osVersion/vendor/deviceType 추정으로 바꾼다.
    public static class SshBannerParser
    {
        public const string Source = "SSH";

        public sealed record Banner(string Raw, string ProtocolVersion, string Software, string? Comments)
        {
            // "OpenSSH_9.6p1" → ("OpenSSH", "9.6p1"). 구분자(_ 또는 -)가 없으면 Version은 null.
            public string Product
            {
                get
                {
                    int i = Software.IndexOfAny(new[] { '_', '-' });
                    return i <= 0 ? Software : Software.Substring(0, i);
                }
            }

            public string? Version
            {
                get
                {
                    int i = Software.IndexOfAny(new[] { '_', '-' });
                    return i <= 0 || i + 1 >= Software.Length ? null : Software.Substring(i + 1);
                }
            }
        }

        // OpenSSH 패키지 버전 → Ubuntu 릴리스(Ubuntu- 꼬리표가 있을 때만 적용).
        internal static readonly IReadOnlyDictionary<string, string> UbuntuByOpenSsh = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["5.3p1"] = "10.04", ["5.9p1"] = "12.04", ["6.6.1p1"] = "14.04", ["7.2p2"] = "16.04", ["7.6p1"] = "18.04",
            ["8.2p1"] = "20.04", ["8.9p1"] = "22.04", ["9.0p1"] = "22.10", ["9.3p1"] = "23.04", ["9.6p1"] = "24.04",
            ["9.7p1"] = "24.10", ["9.9p1"] = "25.04", ["10.0p2"] = "25.10",
        };

        // OpenSSH 패키지 버전 → Debian 릴리스(Debian-/Raspbian- 꼬리표). 7.4p1은 stretch(9)이며 jessie(8)는 6.7p1이다.
        internal static readonly IReadOnlyDictionary<string, string> DebianByOpenSsh = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["5.5p1"] = "6 (squeeze)", ["6.0p1"] = "7 (wheezy)", ["6.7p1"] = "8 (jessie)", ["7.4p1"] = "9 (stretch)",
            ["7.9p1"] = "10 (buster)", ["8.4p1"] = "11 (bullseye)", ["9.2p1"] = "12 (bookworm)", ["10.0p2"] = "13 (trixie)",
        };

        // 패치 레벨(pN)을 떼고 내보내는 RHEL 계열 버전(Low 추정 — macOS도 pN을 떼므로 겹치는 9.x는 넣지 않는다).
        internal static readonly IReadOnlyDictionary<string, string> RhelByOpenSsh = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["5.3"] = "RHEL/CentOS 6", ["7.4"] = "RHEL/CentOS 7", ["8.0"] = "RHEL/CentOS 8", ["8.7"] = "RHEL 9 계열",
        };

        private static readonly Regex BannerRegex = new(@"^SSH-(?<ver>[0-9.]+)-(?<sw>\S+)(?:\s+(?<cm>.*))?$", RegexOptions.CultureInvariant);

        public static bool TryParse(string? line, out Banner banner)
        {
            banner = null!;
            if (string.IsNullOrWhiteSpace(line)) return false;
            string raw = line.Trim();
            Match m = BannerRegex.Match(raw);
            if (!m.Success) return false;
            string? comments = m.Groups["cm"].Success ? m.Groups["cm"].Value.Trim() : null;
            banner = new Banner(raw, m.Groups["ver"].Value, m.Groups["sw"].Value, string.IsNullOrEmpty(comments) ? null : comments);
            return true;
        }

        public static IReadOnlyList<Fact> Facts(string? line)
        {
            if (!TryParse(line, out Banner b)) return Array.Empty<Fact>();
            var facts = new FactList(Source);
            string sw = b.Software;
            string all = b.Raw;

            facts.Add(FactFields.Service, sw, Confidence.High);

            if (Has(sw, "OpenSSH_for_Windows") || Has(all, "Windows"))
            {
                facts.Add(FactFields.Os, "Windows", Confidence.Medium);
            }
            else if (sw.StartsWith("dropbear", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(FactFields.Os, "Embedded Linux", Confidence.Medium);
                facts.Add(FactFields.DeviceType, "embedded", Confidence.Medium);
            }
            else if (Has(sw, "Cisco"))
            {
                facts.Add(FactFields.Os, "Cisco IOS", Confidence.Medium);
                facts.Add(FactFields.Vendor, "Cisco", Confidence.High);
                facts.Add(FactFields.DeviceType, "network", Confidence.Medium);
            }
            else if (Has(sw, "ROSSSH"))
            {
                facts.Add(FactFields.Os, "MikroTik RouterOS", Confidence.Medium);
                facts.Add(FactFields.Vendor, "MikroTik", Confidence.High);
                facts.Add(FactFields.DeviceType, "router", Confidence.Medium);
            }
            else if (Has(sw, "Huawei") || Has(all, "HUAWEI"))
            {
                facts.Add(FactFields.Vendor, "Huawei", Confidence.High);
                facts.Add(FactFields.DeviceType, "network", Confidence.Medium);
            }
            else if (Has(sw, "Comware"))
            {
                facts.Add(FactFields.Vendor, "H3C/HPE", Confidence.Medium);
                facts.Add(FactFields.Os, "Comware", Confidence.Medium);
                facts.Add(FactFields.DeviceType, "network", Confidence.Medium);
            }
            else if (Has(sw, "mod_sftp"))
            {
                facts.Add(FactFields.Service, "ProFTPD mod_sftp", Confidence.High);
                facts.Add(FactFields.Os, "Linux/Unix", Confidence.Low);
            }
            else if (sw.Equals("Go", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(FactFields.Description, "Go crypto/ssh 서버(Gitea/Gogs 등)", Confidence.Low);
            }
            else if (Has(sw, "OpenSSH"))
            {
                AddOpenSshDistro(b, facts);
            }
            else if (Has(sw, "libssh") || Has(sw, "paramiko") || Has(sw, "AsyncSSH") || Has(sw, "Twisted"))
            {
                facts.Add(FactFields.Os, "Linux/Unix", Confidence.Low);
            }

            if (Has(all, "Synology"))
            {
                facts.Add(FactFields.Vendor, "Synology", Confidence.High);
                facts.Add(FactFields.DeviceType, "nas", Confidence.Medium);
            }
            return facts.ToList();
        }

        private static void AddOpenSshDistro(Banner b, FactList facts)
        {
            string? ver = b.Version;           // "9.6p1"
            string comments = b.Comments ?? "";
            string all = b.Raw;

            if (Has(comments, "Raspbian"))
            {
                facts.Add(FactFields.Os, "Linux", Confidence.Medium);
                string deb = ver != null && DebianByOpenSsh.TryGetValue(ver, out string? d) ? $"Raspberry Pi OS (Debian {d})" : "Raspberry Pi OS";
                facts.Add(FactFields.OsVersion, deb, Confidence.Medium);
                facts.Add(FactFields.Vendor, "Raspberry Pi", Confidence.Medium);
                return;
            }
            if (Has(comments, "Ubuntu"))
            {
                facts.Add(FactFields.Os, "Linux", Confidence.Medium);
                string u = ver != null && UbuntuByOpenSsh.TryGetValue(ver, out string? rel) ? $"Ubuntu {rel}" : "Ubuntu";
                facts.Add(FactFields.OsVersion, u, Confidence.Medium);
                return;
            }
            if (Has(comments, "Debian") || Has(comments, "+deb"))
            {
                facts.Add(FactFields.Os, "Linux", Confidence.Medium);
                string d = ver != null && DebianByOpenSsh.TryGetValue(ver, out string? rel) ? $"Debian {rel}" : "Debian";
                facts.Add(FactFields.OsVersion, d, Confidence.Medium);
                return;
            }
            if (Has(all, "FreeBSD"))
            {
                facts.Add(FactFields.Os, "FreeBSD", Confidence.Medium);
                return;
            }
            if (Has(all, "NetBSD")) { facts.Add(FactFields.Os, "NetBSD", Confidence.Medium); return; }
            if (Has(all, "OpenBSD")) { facts.Add(FactFields.Os, "OpenBSD", Confidence.Medium); return; }

            // 꼬리표가 없는 OpenSSH: 유닉스 계열이라는 것만 안다. 패치 레벨 없는 버전은 RHEL 계열일 가능성을 Low로 남긴다.
            facts.Add(FactFields.Os, "Linux/Unix", Confidence.Low);
            if (ver != null && b.Comments == null && !ver.Contains('p') && RhelByOpenSsh.TryGetValue(ver, out string? rhel))
                facts.Add(FactFields.OsVersion, $"{rhel} (추정)", Confidence.Low);
        }

        private static bool Has(string text, string needle) => text.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }
}
