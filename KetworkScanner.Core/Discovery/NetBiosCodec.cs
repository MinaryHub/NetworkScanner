using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace KetworkScanner.Discovery
{
    // NetBIOS 이름 서비스(UDP 137)의 NBSTAT(노드 상태) 요청/응답 인코더·디코더.
    internal static class NetBiosCodec
    {
        public const ushort TypeNbstat = 0x21;
        public const ushort ClassIn = 1;
        // 와일드카드 이름 "*"(나머지 0x00 패딩)을 1급 인코딩(각 니블 + 'A')한 32자
        public const string WildcardEncoded = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        public sealed record NameEntry(string Name, byte Suffix, bool IsGroup, ushort Flags);

        public static byte[] BuildNodeStatusRequest(ushort id)
        {
            var buf = new List<byte>(50);
            AddU16(buf, id);
            AddU16(buf, 0x0000);   // 플래그: 질의, 브로드캐스트 아님
            AddU16(buf, 1);        // QDCOUNT
            AddU16(buf, 0); AddU16(buf, 0); AddU16(buf, 0);
            buf.Add(32);
            buf.AddRange(Encoding.ASCII.GetBytes(WildcardEncoded));
            buf.Add(0);
            AddU16(buf, TypeNbstat);
            AddU16(buf, ClassIn);
            return buf.ToArray();
        }

        // NODE STATUS RESPONSE 파싱. names는 15자 이름(끝 공백 제거)+접미사+그룹 비트, mac은 통계 블록의 UNIT_ID.
        public static bool TryParseNodeStatusResponse(byte[] data, out ushort id, out List<NameEntry> names, out string? mac)
        {
            id = 0;
            names = new List<NameEntry>();
            mac = null;
            try
            {
                if (data.Length < 12) return false;
                int pos = 0;
                id = ReadU16(data, ref pos);
                ushort flags = ReadU16(data, ref pos);
                if ((flags & 0x8000) == 0) return false;   // 응답 아님
                int qd = ReadU16(data, ref pos);
                int an = ReadU16(data, ref pos);
                pos += 4;                                   // NSCOUNT, ARCOUNT
                if (an < 1) return false;

                for (int i = 0; i < qd; i++)
                {
                    if (!SkipName(data, ref pos)) return false;
                    pos += 4;
                }

                if (!SkipName(data, ref pos)) return false;
                if (pos + 10 > data.Length) return false;
                ushort type = ReadU16(data, ref pos);
                pos += 2 + 4;                               // CLASS, TTL
                int rdlen = ReadU16(data, ref pos);
                if (type != TypeNbstat || pos + rdlen > data.Length || rdlen < 1) return false;
                int rdEnd = pos + rdlen;

                int count = data[pos++];
                for (int i = 0; i < count; i++)
                {
                    if (pos + 18 > rdEnd) break;
                    string raw = Encoding.Latin1.GetString(data, pos, 15);
                    byte suffix = data[pos + 15];
                    ushort f = (ushort)((data[pos + 16] << 8) | data[pos + 17]);
                    pos += 18;
                    string name = raw.TrimEnd(' ', '\0');
                    if (name.Length == 0 || HasControlChars(name)) continue;   // __MSBROWSE__ 등
                    names.Add(new NameEntry(name, suffix, (f & 0x8000) != 0, f));
                }

                // 통계 블록의 UNIT_ID(6바이트) = 어댑터 MAC. Samba(nmbd)는 전부 0으로 채우므로 호출자가 구분한다.
                if (pos + 6 <= rdEnd)
                {
                    var sb = new StringBuilder(17);
                    for (int i = 0; i < 6; i++)
                    {
                        if (i > 0) sb.Append(':');
                        sb.Append(data[pos + i].ToString("X2", CultureInfo.InvariantCulture));
                    }
                    mac = sb.ToString();
                }
                return names.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        // 1급 인코딩된 NetBIOS 이름(길이 32 + 'A'..'P' 32자 + 스코프 라벨) → 15자 이름 + 접미(16번째 바이트).
        // pos는 이름 뒤(스코프 종료 0 바이트 다음)로 옮긴다. 형식이 아니면 false이고 pos는 그대로.
        public static bool TryReadEncodedName(byte[] data, ref int pos, out string name, out byte suffix)
        {
            name = ""; suffix = 0;
            if (pos >= data.Length || data[pos] != 32 || pos + 1 + 32 > data.Length) return false;
            var raw = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                int hi = data[pos + 1 + i * 2] - 'A', lo = data[pos + 2 + i * 2] - 'A';
                if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return false;
                raw[i] = (byte)((hi << 4) | lo);
            }
            int p = pos + 1 + 32;
            // 스코프 라벨(보통 0 한 바이트) 건너뛰기
            while (p < data.Length && data[p] != 0) p += 1 + data[p];
            pos = p + 1;
            suffix = raw[15];
            name = Encoding.ASCII.GetString(raw, 0, 15).TrimEnd(' ', '\0');
            return true;
        }

        private static bool HasControlChars(string s)
        {
            foreach (char c in s) if (c < 0x20 || c == 0x7F) return true;
            return false;
        }

        private static bool SkipName(byte[] data, ref int pos)
        {
            while (true)
            {
                if (pos >= data.Length) return false;
                int len = data[pos];
                if (len == 0) { pos++; return true; }
                if ((len & 0xC0) == 0xC0) { pos += 2; return pos <= data.Length; }
                pos += 1 + len;
            }
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
