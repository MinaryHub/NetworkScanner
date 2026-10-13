using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using KetworkScanner.Discovery;

namespace KetworkScanner.Capture
{
    // BOOTP/DHCPv4 메시지(UDP 67/68 페이로드)의 최소 파서. PacketDotNet에 의존하지 않고 직접 읽어 테스트하기 쉽게 한다.
    internal sealed class DhcpMessage
    {
        public const byte OpRequest = 1;   // 클라이언트 → 서버
        public const byte OpReply = 2;     // 서버 → 클라이언트

        public byte Op;
        public byte MessageType;           // 옵션 53: 1=DISCOVER 2=OFFER 3=REQUEST 5=ACK 8=INFORM …
        public string Mac = "";            // chaddr (AA:BB:CC:DD:EE:FF)
        public string ClientIp = "";       // ciaddr (0.0.0.0이면 "")
        public string YourIp = "";         // yiaddr (서버가 배정한 주소)
        public string RequestedIp = "";    // 옵션 50
        public string? Hostname;           // 옵션 12 (없으면 옵션 81 FQDN)
        public string? VendorClass;        // 옵션 60
        public byte[]? ClientId;           // 옵션 61
        public byte[] ParameterRequestList = Array.Empty<byte>(); // 옵션 55
        public readonly Dictionary<byte, byte[]> Options = new();

        public bool IsRequest => Op == OpRequest;

        // 옵션 55를 "1,3,6,15,…" 형태로. Fingerbank 등에서 쓰는 DHCP 핑거프린트 표기.
        public string Fingerprint => string.Join(",", ParameterRequestList.Select(b => b.ToString(CultureInfo.InvariantCulture)));

        // 이 메시지가 말하는 클라이언트 IP. 요청 쪽은 50 → ciaddr, 응답 쪽은 yiaddr → ciaddr 순.
        public string BestIp
        {
            get
            {
                if (IsRequest) return RequestedIp.Length > 0 ? RequestedIp : ClientIp;
                return YourIp.Length > 0 ? YourIp : ClientIp;
            }
        }

        public static string MessageTypeName(byte t) => t switch
        {
            1 => "DISCOVER", 2 => "OFFER", 3 => "REQUEST", 4 => "DECLINE", 5 => "ACK", 6 => "NAK", 7 => "RELEASE", 8 => "INFORM",
            _ => t.ToString(CultureInfo.InvariantCulture),
        };
    }

    internal static class DhcpCodec
    {
        private const int FixedHeaderLength = 236;      // op~file 까지
        private static readonly byte[] MagicCookie = { 0x63, 0x82, 0x53, 0x63 };

        public const byte OptPad = 0, OptHostname = 12, OptRequestedIp = 50, OptMessageType = 53, OptParameterRequestList = 55,
            OptVendorClass = 60, OptClientId = 61, OptClientFqdn = 81, OptEnd = 255;

        public static bool TryParse(ReadOnlySpan<byte> payload, out DhcpMessage msg)
        {
            msg = new DhcpMessage();
            try
            {
                if (payload.Length < FixedHeaderLength + 4) return false;
                msg.Op = payload[0];
                if (msg.Op != DhcpMessage.OpRequest && msg.Op != DhcpMessage.OpReply) return false;
                int hlen = payload[2];
                msg.ClientIp = Ip(payload.Slice(12, 4));
                msg.YourIp = Ip(payload.Slice(16, 4));
                if (hlen == 6) msg.Mac = FormatMac(payload.Slice(28, 6));
                if (!payload.Slice(FixedHeaderLength, 4).SequenceEqual(MagicCookie)) return false;

                int pos = FixedHeaderLength + 4;
                while (pos < payload.Length)
                {
                    byte code = payload[pos++];
                    if (code == OptPad) continue;
                    if (code == OptEnd) break;
                    if (pos >= payload.Length) break;
                    int len = payload[pos++];
                    if (pos + len > payload.Length) break;
                    byte[] data = payload.Slice(pos, len).ToArray();
                    pos += len;
                    msg.Options.TryAdd(code, data);     // 같은 옵션이 반복되면 첫 번째만

                    switch (code)
                    {
                        case OptMessageType: if (len >= 1) msg.MessageType = data[0]; break;
                        case OptHostname: msg.Hostname ??= CleanText(data); break;
                        case OptRequestedIp: if (len == 4) msg.RequestedIp = Ip(data); break;
                        case OptParameterRequestList: msg.ParameterRequestList = data; break;
                        case OptVendorClass: msg.VendorClass = CleanText(data); break;
                        case OptClientId: msg.ClientId = data; break;
                        case OptClientFqdn:
                            // flags(1) rcode1(1) rcode2(1) 뒤에 이름. S비트(0x04)면 DNS 와이어 형식, 아니면 ASCII.
                            if (len > 3)
                            {
                                string fqdn = (data[0] & 0x04) != 0 ? DecodeWireName(data.AsSpan(3)) : CleanText(data.AsSpan(3).ToArray());
                                msg.Hostname ??= fqdn.Split('.')[0];
                            }
                            break;
                    }
                }
                // chaddr가 비어 있고 클라이언트 ID가 이더넷 타입(1)+6바이트면 그걸 MAC으로 쓴다.
                if (msg.Mac.Length == 0 && msg.ClientId is { Length: 7 } cid && cid[0] == 1) msg.Mac = FormatMac(cid.AsSpan(1, 6));
                if (msg.Hostname != null && msg.Hostname.Length == 0) msg.Hostname = null;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // 테스트/도구용: BOOTREQUEST 페이로드를 조립한다.
        public static byte[] BuildRequest(byte messageType, byte[] mac, string? hostname, string? vendorClass, byte[]? paramList,
                                          string? requestedIp = null, string? clientIp = null)
        {
            var buf = new byte[FixedHeaderLength];
            buf[0] = DhcpMessage.OpRequest; buf[1] = 1; buf[2] = 6;
            buf[4] = 0x12; buf[5] = 0x34; buf[6] = 0x56; buf[7] = 0x78; // xid
            if (clientIp != null) System.Net.IPAddress.Parse(clientIp).GetAddressBytes().CopyTo(buf, 12);
            Array.Copy(mac, 0, buf, 28, 6);
            var opts = new List<byte>(MagicCookie) { OptMessageType, 1, messageType };
            if (requestedIp != null) { opts.Add(OptRequestedIp); opts.Add(4); opts.AddRange(System.Net.IPAddress.Parse(requestedIp).GetAddressBytes()); }
            if (hostname != null) { byte[] h = Encoding.ASCII.GetBytes(hostname); opts.Add(OptHostname); opts.Add((byte)h.Length); opts.AddRange(h); }
            if (vendorClass != null) { byte[] v = Encoding.ASCII.GetBytes(vendorClass); opts.Add(OptVendorClass); opts.Add((byte)v.Length); opts.AddRange(v); }
            if (paramList != null) { opts.Add(OptParameterRequestList); opts.Add((byte)paramList.Length); opts.AddRange(paramList); }
            opts.Add(OptClientId); opts.Add(7); opts.Add(1); opts.AddRange(mac);
            opts.Add(OptEnd);
            return buf.Concat(opts).ToArray();
        }

        private static string Ip(ReadOnlySpan<byte> b)
        {
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) return "";
            return new System.Net.IPAddress(b).ToString();
        }

        internal static string FormatMac(ReadOnlySpan<byte> b)
        {
            if (b.Length != 6) return "";
            bool allZero = true;
            foreach (byte x in b) if (x != 0) { allZero = false; break; }
            if (allZero) return "";
            var sb = new StringBuilder(17);
            for (int i = 0; i < 6; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(b[i].ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        // 제어 문자/널 패딩을 걷어낸 ASCII 문자열.
        internal static string CleanText(byte[] data)
        {
            string s = Encoding.UTF8.GetString(data).TrimEnd('\0').Trim();
            var sb = new StringBuilder(s.Length);
            foreach (char c in s) if (!char.IsControl(c)) sb.Append(c);
            return sb.ToString();
        }

        private static string DecodeWireName(ReadOnlySpan<byte> data)
        {
            var labels = new List<string>();
            int pos = 0;
            while (pos < data.Length)
            {
                int len = data[pos++];
                if (len == 0 || pos + len > data.Length) break;
                labels.Add(Encoding.ASCII.GetString(data.Slice(pos, len)));
                pos += len;
            }
            return string.Join(".", labels);
        }
    }

    // DHCP 옵션 55(파라미터 요청 목록)와 옵션 60(벤더 클래스)에서 OS를 추정하는 Fingerbank 식 소형 테이블.
    // 정확히 일치하면 High, 한쪽이 다른 쪽의 접두어(4개 이상 공유)면 Medium. 표 항목은 공개된 흔한 패턴으로 완전하지 않다.
    internal static class DhcpFingerprints
    {
        public sealed record Result(string Os, Confidence Confidence, string Fingerprint);

        // (핑거프린트, OS). 정확 일치를 먼저 찾고, 없으면 가장 긴 접두어 일치를 고른다.
        internal static readonly (string Fingerprint, string Os)[] Table =
        {
            ("1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows 10/11"),
            ("1,3,6,15,31,33,43,44,46,47,119,121,249,252,17", "Windows 11"),
            ("1,15,3,6,44,46,47,31,33,121,249,43", "Windows 7"),
            ("1,15,3,6,44,46,47,31,33,121,249,252,43", "Windows 8/8.1"),
            ("1,15,3,6,44,46,47,31,33,249,43", "Windows XP"),
            ("1,121,3,6,15,119,252,95,44,46", "macOS/iOS"),
            ("1,121,3,6,15,119,252,95,44,46,47", "macOS"),
            ("1,121,3,6,15,119,252", "iOS/iPadOS"),
            ("1,3,6,15,119,252", "iOS (legacy)"),
            ("1,3,6,15,26,28,51,58,59,43", "Android"),
            ("1,3,6,15,26,28,51,58,59,43,114", "Android 11+"),
            ("1,3,6,15,26,28,51,58,59", "Android (legacy)"),
            ("1,28,2,3,15,6,119,12,44,47,26,121,42", "Linux (dhclient)"),
            ("1,28,2,3,15,6,12", "Linux (dhclient)"),
            ("1,28,2,3,15,6,119,12", "Linux (dhclient/NetworkManager)"),
            ("1,121,33,3,6,12,15,26,28,42,51,54,58,59,119", "Linux (systemd-networkd)"),
            ("1,3,6,12,15,17,28,42,121,249", "Linux (udhcpc/BusyBox)"),
            ("1,3,6,12,15,28,42,121", "Linux (udhcpc/OpenWrt)"),
            ("1,3,6,12,15,28,42,121,119,249", "Chrome OS"),
            ("1,3,6,15,28,33,51,58,59", "Samsung Smart TV (Tizen)"),
            ("1,3,15,6", "PlayStation 4/5"),
            ("1,3,6,15", "PlayStation 3 / embedded"),
            ("1,66,6,3,67,12,150,43", "Cisco IP Phone"),
            ("1,3,6,12,15,28,40,41,42", "Linux (embedded/printer)"),
            ("1,3,6,15,43,51,54,58,59", "Nintendo Switch"),
            ("1,3,6,12,15,17,23,28,29,31,33,40,41,42,119,121,249,252", "Linux (dhcpcd)"),
            ("1,2,3,6,12,15,26,28,42,51,53,54,58,59,119,121", "FreeBSD/pfSense"),
        };

        public static Result? MatchList(IEnumerable<byte> parameterRequestList)
        {
            string fp = string.Join(",", parameterRequestList.Select(b => b.ToString(CultureInfo.InvariantCulture)));
            return MatchFingerprint(fp);
        }

        public static Result? MatchFingerprint(string fingerprint)
        {
            if (string.IsNullOrEmpty(fingerprint)) return null;
            foreach (var (fp, os) in Table)
                if (fp == fingerprint) return new Result(os, Confidence.High, fp);

            // 접두어 일치: 공유 길이가 가장 긴 항목을 고른다(최소 4개 옵션).
            string[] mine = fingerprint.Split(',');
            Result? best = null; int bestLen = 0;
            foreach (var (fp, os) in Table)
            {
                string[] theirs = fp.Split(',');
                int n = Math.Min(mine.Length, theirs.Length);
                if (n < 4 || n <= bestLen) continue;
                bool ok = true;
                for (int i = 0; i < n; i++) if (mine[i] != theirs[i]) { ok = false; break; }
                if (ok) { best = new Result(os, Confidence.Medium, fp); bestLen = n; }
            }
            return best;
        }

        private static readonly Regex AndroidClass = new(@"^android-dhcp-(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // 옵션 60 벤더 클래스 → (os, vendor, deviceType) 힌트. 모르는 값이면 빈 목록.
        public static IReadOnlyList<Fact> FactsFromVendorClass(string? vendorClass, string source)
        {
            var facts = new List<Fact>();
            if (string.IsNullOrWhiteSpace(vendorClass)) return facts;
            string vc = vendorClass.Trim();

            if (vc.StartsWith("MSFT", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Os, "Windows", source, Confidence.High));
            else if (AndroidClass.Match(vc) is { Success: true } m)
                facts.Add(new Fact(FactFields.Os, "Android " + m.Groups[1].Value, source, Confidence.High));
            else if (vc.StartsWith("dhcpcd", StringComparison.OrdinalIgnoreCase) || vc.StartsWith("udhcp", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Os, "Linux", source, Confidence.Medium));
            else if (vc.Contains("Linux", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Os, "Linux", source, Confidence.Medium));
            else if (vc.StartsWith("Cisco", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(new Fact(FactFields.Vendor, "Cisco", source, Confidence.High));
                if (vc.Contains("Phone", StringComparison.OrdinalIgnoreCase) || vc.Contains("CP-", StringComparison.OrdinalIgnoreCase))
                    facts.Add(new Fact(FactFields.DeviceType, "ipphone", source, Confidence.Medium));
            }
            else if (vc.Contains("PlayStation", StringComparison.OrdinalIgnoreCase) || vc.StartsWith("PS4", StringComparison.OrdinalIgnoreCase) || vc.StartsWith("PS5", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(new Fact(FactFields.Os, "PlayStation", source, Confidence.High));
                facts.Add(new Fact(FactFields.DeviceType, "console", source, Confidence.High));
            }
            else if (vc.Contains("Xbox", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(new Fact(FactFields.Os, "Xbox", source, Confidence.High));
                facts.Add(new Fact(FactFields.DeviceType, "console", source, Confidence.High));
            }
            else if (vc.Contains("SAMSUNG", StringComparison.OrdinalIgnoreCase))
            {
                facts.Add(new Fact(FactFields.Vendor, "Samsung", source, Confidence.Medium));
                if (vc.Contains("TV", StringComparison.OrdinalIgnoreCase)) facts.Add(new Fact(FactFields.DeviceType, "tv", source, Confidence.Medium));
            }
            else if (vc.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase) || vc.StartsWith("HP ", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Vendor, "HP", source, Confidence.Medium));
            else if (vc.Contains("Polycom", StringComparison.OrdinalIgnoreCase) || vc.Contains("Yealink", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.DeviceType, "ipphone", source, Confidence.Medium));
            else if (vc.StartsWith("PXEClient", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Description, "PXE boot", source, Confidence.Low));
            else if (vc.Contains("ubnt", StringComparison.OrdinalIgnoreCase))
                facts.Add(new Fact(FactFields.Vendor, "Ubiquiti", source, Confidence.Medium));

            return facts;
        }
    }
}
