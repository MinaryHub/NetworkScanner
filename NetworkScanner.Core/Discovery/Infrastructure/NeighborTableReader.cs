using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery.Infrastructure
{
    // OS의 이웃 테이블(IPv4 ARP + IPv6 ND)을 권한 없이 읽는다.
    //  macOS:   `ndp -an`(IPv6) + `arp -an`(IPv4)
    //  Linux:   /proc/net/arp(IPv4) + `ip -6 neigh show`(IPv6, 없으면 무시)
    //  Windows: iphlpapi GetIpNetTable2(AF_UNSPEC) — 행 레이아웃은 Platform/WindowsIpNetTableArpResolver와 동일
    // MAC은 "AA-BB-CC-DD-EE-FF"로 정규화하고, 미완성/전부 0/멀티캐스트 항목은 버린다. 절대 예외를 던지지 않는다.
    public static class NeighborTableReader
    {
        public static IReadOnlyList<(string Ip, string Mac, string Interface, bool IsIpv6)> Read()
        {
            var entries = new List<(string Ip, string Mac, string Interface, bool IsIpv6)>();
            try
            {
                if (OperatingSystem.IsMacOS())
                {
                    entries.AddRange(ParseNdp(RunProcess("ndp", "-an")));
                    entries.AddRange(ParseArpAn(RunProcess("arp", "-an")));
                }
                else if (OperatingSystem.IsLinux())
                {
                    try { entries.AddRange(ParseProcArp(File.ReadAllText("/proc/net/arp"))); } catch { }
                    entries.AddRange(ParseIpNeigh(RunProcess("ip", "-6 neigh show")));
                }
                else if (OperatingSystem.IsWindows())
                {
                    entries.AddRange(ReadWindows());
                }
            }
            catch (Exception ex)
            {
                AppLogger.LogDebug(nameof(NeighborTableReader), "이웃 테이블 읽기 실패: " + ex.Message);
            }
            return Dedupe(entries);
        }

        // ---- 텍스트 파서 (순수 함수, 테스트 대상) ----

        // macOS `ndp -an`:
        //   Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs
        //   fe80::cb5:6cde:3293:5e1e%en0    7a:5e:35:7a:e0:bc    en0 23h51m30s S
        //   fe80::1%lo0                     (incomplete)         lo0 permanent R
        internal static List<(string Ip, string Mac, string Interface, bool IsIpv6)> ParseNdp(string text)
        {
            var list = new List<(string, string, string, bool)>();
            if (string.IsNullOrEmpty(text)) return list;
            foreach (string rawLine in text.Split('\n'))
            {
                string[] cols = rawLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 3 || !cols[0].Contains(':')) continue; // 헤더/빈 줄
                string? mac = InfrastructureFacts.MacFromText(cols[1]);
                if (!InfrastructureFacts.IsUsableMac(mac)) continue;
                (string addr, string zone) = SplitZone(cols[0]);
                if (!IsUsableIpv6(addr)) continue;
                string iface = cols[2].Length > 0 ? cols[2] : zone;
                list.Add((addr, mac!, iface, true));
            }
            return list;
        }

        // BSD/macOS/Linux `arp -an`:
        //   ? (192.168.75.1) at 0:23:aa:3a:82:ba on en0 ifscope [ethernet]
        //   ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        private static readonly Regex ArpAnRegex = new(@"\(([\d.]+)\) at ([0-9A-Fa-f:]{11,17})", RegexOptions.Compiled);
        private static readonly Regex ArpAnIfaceRegex = new(@"\bon (\S+)", RegexOptions.Compiled);

        internal static List<(string Ip, string Mac, string Interface, bool IsIpv6)> ParseArpAn(string text)
        {
            var list = new List<(string, string, string, bool)>();
            if (string.IsNullOrEmpty(text)) return list;
            foreach (string line in text.Split('\n'))
            {
                Match m = ArpAnRegex.Match(line);
                if (!m.Success) continue;
                string? mac = InfrastructureFacts.MacFromText(m.Groups[2].Value);
                if (!InfrastructureFacts.IsUsableMac(mac) || !IsUsableIpv4(m.Groups[1].Value)) continue;
                Match mi = ArpAnIfaceRegex.Match(line);
                list.Add((m.Groups[1].Value, mac!, mi.Success ? mi.Groups[1].Value : "", false));
            }
            return list;
        }

        // Linux `ip [-6] neigh show`:
        //   fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
        //   2001:db8::7 dev eth0  FAILED
        //   192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
        internal static List<(string Ip, string Mac, string Interface, bool IsIpv6)> ParseIpNeigh(string text)
        {
            var list = new List<(string, string, string, bool)>();
            if (string.IsNullOrEmpty(text)) return list;
            foreach (string line in text.Split('\n'))
            {
                string[] cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 3) continue;
                string addr = cols[0];
                string iface = "", macText = "";
                bool failed = false;
                for (int i = 1; i < cols.Length; i++)
                {
                    if (cols[i] == "dev" && i + 1 < cols.Length) iface = cols[++i];
                    else if (cols[i] == "lladdr" && i + 1 < cols.Length) macText = cols[++i];
                    else if (cols[i] == "FAILED" || cols[i] == "INCOMPLETE") failed = true;
                }
                if (failed || macText.Length == 0) continue;
                string? mac = InfrastructureFacts.MacFromText(macText);
                if (!InfrastructureFacts.IsUsableMac(mac)) continue;
                bool v6 = addr.Contains(':');
                (addr, _) = SplitZone(addr);
                if (v6 ? !IsUsableIpv6(addr) : !IsUsableIpv4(addr)) continue;
                list.Add((addr, mac!, iface, v6));
            }
            return list;
        }

        // Linux /proc/net/arp. Flags의 0x2(ATF_COM) 비트가 켜진 항목만 완료된 것.
        internal static List<(string Ip, string Mac, string Interface, bool IsIpv6)> ParseProcArp(string text)
        {
            var list = new List<(string, string, string, bool)>();
            if (string.IsNullOrEmpty(text)) return list;
            string[] lines = text.Split('\n');
            for (int i = 1; i < lines.Length; i++) // 첫 줄은 헤더
            {
                string[] cols = lines[i].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 6) continue;
                string flagsText = cols[2].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? cols[2].Substring(2) : cols[2];
                if (!int.TryParse(flagsText, System.Globalization.NumberStyles.HexNumber, null, out int flags) || (flags & 0x2) == 0) continue;
                string? mac = InfrastructureFacts.MacFromText(cols[3]);
                if (!InfrastructureFacts.IsUsableMac(mac) || !IsUsableIpv4(cols[0])) continue;
                list.Add((cols[0], mac!, cols[5], false));
            }
            return list;
        }

        // ---- Windows: GetIpNetTable2(AF_UNSPEC) ----

        internal const int WindowsRowSize = 88;
        private const int WinTableHeaderSize = 8;
        private const int WinOffFamily = 0;
        private const int WinOffSinAddr = 4;      // sockaddr_in.sin_addr
        private const int WinOffSin6Addr = 8;     // sockaddr_in6.sin6_addr (16바이트)
        private const int WinOffSin6ScopeId = 24;
        private const int WinOffInterfaceIndex = 28;
        private const int WinOffPhysicalAddress = 40;
        private const int WinOffPhysicalAddressLength = 72;
        private const int WinOffState = 76;
        private const ushort WinAfUnspec = 0, WinAfInet = 2, WinAfInet6 = 23;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetIpNetTable2(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern void FreeMibTable(IntPtr memory);

        [SupportedOSPlatform("windows")]
        private static List<(string Ip, string Mac, string Interface, bool IsIpv6)> ReadWindows()
        {
            var list = new List<(string, string, string, bool)>();
            IntPtr table = IntPtr.Zero;
            try
            {
                if (GetIpNetTable2(WinAfUnspec, out table) != 0 || table == IntPtr.Zero) return list;
                Dictionary<int, string> ifNames = InterfaceNamesByIndex();
                uint count = (uint)Marshal.ReadInt32(table);
                var row = new byte[WindowsRowSize];
                for (uint i = 0; i < count; i++)
                {
                    Marshal.Copy(table + WinTableHeaderSize + (int)(i * WindowsRowSize), row, 0, WindowsRowSize);
                    var parsed = ParseWindowsRow(row);
                    if (parsed == null) continue;
                    string iface = ifNames.TryGetValue(parsed.Value.InterfaceIndex, out string? n) ? n : "if" + parsed.Value.InterfaceIndex;
                    list.Add((parsed.Value.Ip, parsed.Value.Mac, iface, parsed.Value.IsIpv6));
                }
            }
            catch { }
            finally
            {
                if (table != IntPtr.Zero) { try { FreeMibTable(table); } catch { } }
            }
            return list;
        }

        // MIB_IPNET_ROW2(88바이트) 하나를 해석한다. AF_INET(2)은 @4에 4바이트, AF_INET6(23)은 @8에 16바이트 주소.
        // Reachable(2)~Permanent(6) 상태이고 MAC이 6바이트인 유니캐스트 항목만 돌려준다.
        internal static (string Ip, string Mac, int InterfaceIndex, bool IsIpv6)? ParseWindowsRow(ReadOnlySpan<byte> row)
        {
            if (row.Length < WindowsRowSize) return null;
            ushort family = BinaryPrimitives.ReadUInt16LittleEndian(row.Slice(WinOffFamily, 2));
            int state = BinaryPrimitives.ReadInt32LittleEndian(row.Slice(WinOffState, 4));
            if (state < 2 || state > 6) return null; // Unreachable(0)/Incomplete(1) 제외
            uint physLen = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(WinOffPhysicalAddressLength, 4));
            if (physLen != 6) return null;
            string? mac = InfrastructureFacts.MacFromBytes(row.Slice(WinOffPhysicalAddress, 6));
            if (!InfrastructureFacts.IsUsableMac(mac)) return null;
            int ifIndex = BinaryPrimitives.ReadInt32LittleEndian(row.Slice(WinOffInterfaceIndex, 4));

            if (family == WinAfInet)
            {
                string ip = new IPAddress(row.Slice(WinOffSinAddr, 4).ToArray()).ToString();
                return IsUsableIpv4(ip) ? (ip, mac!, ifIndex, false) : null;
            }
            if (family == WinAfInet6)
            {
                var addr = new IPAddress(row.Slice(WinOffSin6Addr, 16).ToArray());
                string ip = addr.ToString();
                if (!IsUsableIpv6(ip)) return null;
                _ = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(WinOffSin6ScopeId, 4)); // 존 ID는 인터페이스 인덱스로 대신 표현
                return (ip, mac!, ifIndex, true);
            }
            return null;
        }

        private static Dictionary<int, string> InterfaceNamesByIndex()
        {
            var map = new Dictionary<int, string>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    IPInterfaceProperties props;
                    try { props = nic.GetIPProperties(); } catch { continue; }
                    try { map[props.GetIPv4Properties().Index] = nic.Name; } catch { }
                    try { map[props.GetIPv6Properties().Index] = nic.Name; } catch { }
                }
            }
            catch { }
            return map;
        }

        // ---- 공통 ----

        internal static (string Address, string Zone) SplitZone(string address)
        {
            int pct = address.IndexOf('%');
            return pct < 0 ? (address, "") : (address.Substring(0, pct), address.Substring(pct + 1));
        }

        internal static bool IsUsableIpv4(string text)
        {
            if (!IPAddress.TryParse(text, out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 0 || b[0] == 127 || b[0] >= 224) return false; // 0/8, 루프백, 멀티캐스트/브로드캐스트
            return true;
        }

        internal static bool IsUsableIpv6(string text)
        {
            if (!IPAddress.TryParse(text, out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
            if (ip.IsIPv6Multicast || IPAddress.IPv6Loopback.Equals(ip) || IPAddress.IPv6Any.Equals(ip)) return false;
            return true;
        }

        private static List<(string Ip, string Mac, string Interface, bool IsIpv6)> Dedupe(List<(string Ip, string Mac, string Interface, bool IsIpv6)> entries)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<(string, string, string, bool)>(entries.Count);
            foreach (var e in entries)
            {
                if (seen.Add(e.Ip + "|" + e.Mac)) result.Add(e);
            }
            return result;
        }

        private static string RunProcess(string fileName, string arguments)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName, arguments)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using Process? p = Process.Start(psi);
                if (p == null) return "";
                string output = p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(3000)) { try { p.Kill(); } catch { } }
                return output;
            }
            catch
            {
                return ""; // 명령이 없거나 실행 불가 → 그 출처는 비어 있는 것으로 본다
            }
        }
    }

    // OS 이웃 테이블을 INetworkDiscovery로 감싼다. IPv4 → mac + seenBy, IPv6은 같은 MAC의 IPv4 호스트에 ipv6로 붙인다.
    public sealed class NeighborDiscovery : INetworkDiscovery
    {
        private readonly Func<IReadOnlyList<(string Ip, string Mac, string Interface, bool IsIpv6)>> _reader;

        public NeighborDiscovery() : this(NeighborTableReader.Read) { }

        internal NeighborDiscovery(Func<IReadOnlyList<(string Ip, string Mac, string Interface, bool IsIpv6)>> reader)
        {
            _reader = reader;
        }

        public string Name => InfrastructureFacts.SourceNeighborTable;

        public Task<IReadOnlyDictionary<string, IReadOnlyList<Fact>>> DiscoverAsync(int timeoutMs, CancellationToken ct)
        {
            return Task.Run(() =>
            {
                IReadOnlyList<(string Ip, string Mac, string Interface, bool IsIpv6)> entries;
                try { entries = _reader(); }
                catch (Exception ex)
                {
                    AppLogger.LogDebug(nameof(NeighborDiscovery), "읽기 실패: " + ex.Message);
                    entries = Array.Empty<(string, string, string, bool)>();
                }
                return BuildFacts(entries);
            }, ct);
        }

        internal static IReadOnlyDictionary<string, IReadOnlyList<Fact>> BuildFacts(IReadOnlyList<(string Ip, string Mac, string Interface, bool IsIpv6)> entries)
        {
            const string source = InfrastructureFacts.SourceNeighborTable;
            var result = new Dictionary<string, HostFacts>(StringComparer.Ordinal);
            HostFacts Of(string key)
            {
                if (!result.TryGetValue(key, out HostFacts? f)) { f = new HostFacts(key); result[key] = f; }
                return f;
            }

            var ipv4ByMac = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (var e in entries.Where(e => !e.IsIpv6))
            {
                HostFacts f = Of(e.Ip);
                f.Add(FactFields.Mac, e.Mac, source, Confidence.High);
                f.Add(InfrastructureFacts.SeenByField, InfrastructureFacts.SeenByNeighborTable, source, Confidence.Medium);
                if (!ipv4ByMac.TryGetValue(e.Mac, out List<string>? ips)) { ips = new List<string>(); ipv4ByMac[e.Mac] = ips; }
                if (!ips.Contains(e.Ip)) ips.Add(e.Ip);
            }

            foreach (var e in entries.Where(e => e.IsIpv6))
            {
                if (ipv4ByMac.TryGetValue(e.Mac, out List<string>? ips))
                {
                    foreach (string ip4 in ips) Of(ip4).Add(FactFields.Ipv6, e.Ip, source, Confidence.High);
                }
                else
                {
                    HostFacts f = Of(InfrastructureFacts.V6Key(e.Ip));
                    f.Add(FactFields.Mac, e.Mac, source, Confidence.High);
                    f.Add(InfrastructureFacts.SeenByField, InfrastructureFacts.SeenByNeighborTable, source, Confidence.Medium);
                }
            }

            return result.ToDictionary(kv => kv.Key, kv => kv.Value.All, StringComparer.Ordinal);
        }
    }
}
