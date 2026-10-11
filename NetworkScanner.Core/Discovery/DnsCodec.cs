using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace NetworkScanner.Discovery
{
    // DNS/mDNS 메시지의 최소 인코더/디코더. 질의 1건 생성과, 이름 압축 포인터를 포함한 응답 파싱을 다룬다.
    internal static class DnsCodec
    {
        public const ushort TypeA = 1;
        public const ushort TypePtr = 12;
        public const ushort TypeTxt = 16;
        public const ushort TypeAaaa = 28;
        public const ushort TypeSrv = 33;
        public const ushort ClassIn = 1;
        // mDNS QU(unicast-response) 비트가 켜진 IN 클래스
        public const ushort ClassInUnicast = 0x8001;

        // Data: A/AAAA → 주소, PTR/CNAME → 이름, TXT → "k=v" 항목을 ';'로 연결, 그 외 → hex
        public sealed record Record(string Name, ushort Type, ushort Class, uint Ttl, string Data);

        public sealed class Response
        {
            public ushort Id;
            public ushort Flags;
            public bool IsResponse => (Flags & 0x8000) != 0;
            public List<Record> Answers = new();
            public List<Record> Authority = new();
            public List<Record> Additional = new();
        }

        public static string ReverseName(System.Net.IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length != 4) throw new ArgumentException("IPv4 only", nameof(ip));
            return string.Create(CultureInfo.InvariantCulture, $"{b[3]}.{b[2]}.{b[1]}.{b[0]}.in-addr.arpa");
        }

        public static byte[] BuildQuery(ushort id, string name, ushort qtype, ushort qclass)
        {
            var buf = new List<byte>(64);
            AddU16(buf, id);
            AddU16(buf, 0);      // 표준 질의, RD=0 (mDNS 관례)
            AddU16(buf, 1);      // QDCOUNT
            AddU16(buf, 0); AddU16(buf, 0); AddU16(buf, 0);
            foreach (string label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                if (bytes.Length > 63) throw new ArgumentException("label too long", nameof(name));
                buf.Add((byte)bytes.Length);
                buf.AddRange(bytes);
            }
            buf.Add(0);
            AddU16(buf, qtype);
            AddU16(buf, qclass);
            return buf.ToArray();
        }

        public static bool TryParseResponse(byte[] data, out Response response)
        {
            response = new Response();
            try
            {
                if (data.Length < 12) return false;
                int pos = 0;
                response.Id = ReadU16(data, ref pos);
                response.Flags = ReadU16(data, ref pos);
                int qd = ReadU16(data, ref pos);
                int an = ReadU16(data, ref pos);
                int ns = ReadU16(data, ref pos);
                int ar = ReadU16(data, ref pos);

                for (int i = 0; i < qd; i++)
                {
                    if (!TryReadName(data, ref pos, out _)) return false;
                    pos += 4;
                    if (pos > data.Length) return false;
                }
                if (!ReadRecords(data, ref pos, an, response.Answers)) return false;
                if (!ReadRecords(data, ref pos, ns, response.Authority)) return false;
                // Additional은 잘려 있어도 앞부분까지는 살린다(best effort).
                ReadRecords(data, ref pos, ar, response.Additional);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool ReadRecords(byte[] data, ref int pos, int count, List<Record> dst)
        {
            for (int i = 0; i < count; i++)
            {
                if (!TryReadName(data, ref pos, out string name)) return false;
                if (pos + 10 > data.Length) return false;
                ushort type = ReadU16(data, ref pos);
                ushort cls = ReadU16(data, ref pos);
                uint ttl = (uint)(ReadU16(data, ref pos) << 16) | ReadU16(data, ref pos);
                int rdlen = ReadU16(data, ref pos);
                if (pos + rdlen > data.Length) return false;
                dst.Add(new Record(name, type, (ushort)(cls & 0x7FFF), ttl, DecodeRData(data, pos, rdlen, type)));
                pos += rdlen;
            }
            return true;
        }

        private static string DecodeRData(byte[] data, int pos, int len, ushort type)
        {
            switch (type)
            {
                case TypeA when len == 4:
                    return string.Create(CultureInfo.InvariantCulture, $"{data[pos]}.{data[pos + 1]}.{data[pos + 2]}.{data[pos + 3]}");
                case TypeAaaa when len == 16:
                    return new System.Net.IPAddress(data.AsSpan(pos, 16)).ToString();
                case TypePtr:
                case 5: // CNAME
                    {
                        int p = pos;
                        return TryReadName(data, ref p, out string n) ? n : "";
                    }
                case TypeTxt:
                    {
                        var parts = new List<string>();
                        int p = pos, end = pos + len;
                        while (p < end)
                        {
                            int l = data[p++];
                            if (p + l > end) break;
                            if (l > 0) parts.Add(Encoding.UTF8.GetString(data, p, l));
                            p += l;
                        }
                        return string.Join(";", parts);
                    }
                case TypeSrv when len >= 6:
                    {
                        int p = pos + 4;
                        int port = ReadU16(data, ref p);
                        return TryReadName(data, ref p, out string target) ? $"{target}:{port}" : "";
                    }
                default:
                    return Convert.ToHexString(data, pos, len).ToLowerInvariant();
            }
        }

        // 압축 포인터(0xC0xx)를 따라가되 루프를 막기 위해 점프 횟수를 제한한다. 이름은 점으로 연결하고 끝 점은 뺀다.
        internal static bool TryReadName(byte[] data, ref int pos, out string name)
        {
            var sb = new StringBuilder();
            int p = pos;
            int jumps = 0;
            int endAfterFirstPointer = -1;
            while (true)
            {
                if (p >= data.Length) { name = ""; return false; }
                int len = data[p];
                if (len == 0)
                {
                    p++;
                    break;
                }
                if ((len & 0xC0) == 0xC0)
                {
                    if (p + 1 >= data.Length || ++jumps > 16) { name = ""; return false; }
                    int target = ((len & 0x3F) << 8) | data[p + 1];
                    if (endAfterFirstPointer < 0) endAfterFirstPointer = p + 2;
                    p = target;
                    continue;
                }
                if ((len & 0xC0) != 0 || p + 1 + len > data.Length) { name = ""; return false; }
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.UTF8.GetString(data, p + 1, len));
                p += 1 + len;
                if (sb.Length > 512) { name = ""; return false; }
            }
            pos = endAfterFirstPointer >= 0 ? endAfterFirstPointer : p;
            name = sb.ToString();
            return true;
        }

        private static ushort ReadU16(byte[] data, ref int pos)
        {
            ushort v = (ushort)((data[pos] << 8) | data[pos + 1]);
            pos += 2;
            return v;
        }

        private static void AddU16(List<byte> buf, ushort v)
        {
            buf.Add((byte)(v >> 8));
            buf.Add((byte)v);
        }
    }
}
