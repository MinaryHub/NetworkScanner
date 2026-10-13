using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace KetworkScanner.Discovery.Infrastructure
{
    // SNMP 걷기(GETNEXT/GETBULK)에 필요한 BER 인코더/디코더. SnmpCodec은 GetRequest/Response 생성과 "표시용 문자열" 파싱만
    // 다루므로, 여기서는 임의 PDU 타입과 원시 값 바이트(Raw)를 보존하는 디코더를 보탠다.
    // 인코딩은 SnmpCodec의 Tlv/EncodeOid/EncodeInteger를 재사용한다. 모든 읽기는 경계 검사를 하며 예외를 던지지 않는다.
    internal static class SnmpBer
    {
        public const byte PduGetRequest = 0xA0;
        public const byte PduGetNext = 0xA1;
        public const byte PduResponse = 0xA2;
        public const byte PduGetBulk = 0xA5;

        public const byte TagInteger = 0x02;
        public const byte TagOctetString = 0x04;
        public const byte TagNull = 0x05;
        public const byte TagOid = 0x06;
        public const byte TagSequence = 0x30;
        public const byte TagIpAddress = 0x40;
        public const byte TagCounter32 = 0x41;
        public const byte TagGauge32 = 0x42;
        public const byte TagTimeTicks = 0x43;
        public const byte TagCounter64 = 0x46;
        public const byte TagNoSuchObject = 0x80;
        public const byte TagNoSuchInstance = 0x81;
        public const byte TagEndOfMibView = 0x82;

        public readonly record struct VarBind(string Oid, byte Tag, byte[] Raw);

        // 디코딩된 메시지. GetBulk 요청이면 ErrorStatus/ErrorIndex 자리에 non-repeaters/max-repetitions가 들어 있다.
        public sealed class Pdu
        {
            public int Version;
            public string Community = "";
            public byte Type;
            public int RequestId;
            public int ErrorStatus;
            public int ErrorIndex;
            public List<VarBind> VarBinds = new();
        }

        // ---- 인코딩 ----

        public static byte[] BuildGetNext(string community, int requestId, string oid)
            => BuildMessage(community, PduGetNext, requestId, 0, 0, new[] { new VarBind(oid, TagNull, Array.Empty<byte>()) });

        public static byte[] BuildGetBulk(string community, int requestId, string oid, int nonRepeaters, int maxRepetitions)
            => BuildMessage(community, PduGetBulk, requestId, nonRepeaters, maxRepetitions, new[] { new VarBind(oid, TagNull, Array.Empty<byte>()) });

        // 테스트/시뮬레이터용 Response. Raw는 태그의 내용 바이트 그대로(INTEGER는 2의 보수, OID는 base128 본문).
        public static byte[] BuildResponse(string community, int requestId, int errorStatus, int errorIndex, IEnumerable<VarBind> varbinds)
            => BuildMessage(community, PduResponse, requestId, errorStatus, errorIndex, varbinds);

        public static byte[] BuildMessage(string community, byte pduType, int requestId, int field1, int field2, IEnumerable<VarBind> varbinds)
        {
            var list = new List<byte>();
            foreach (VarBind vb in varbinds)
                list.AddRange(SnmpCodec.Tlv(TagSequence, Concat(SnmpCodec.EncodeOid(vb.Oid), SnmpCodec.Tlv(vb.Tag, vb.Raw))));

            byte[] pdu = SnmpCodec.Tlv(pduType, Concat(
                SnmpCodec.EncodeInteger(requestId),
                SnmpCodec.EncodeInteger(field1),
                SnmpCodec.EncodeInteger(field2),
                SnmpCodec.Tlv(TagSequence, list.ToArray())));
            return SnmpCodec.Tlv(TagSequence, Concat(
                SnmpCodec.EncodeInteger(SnmpCodec.VersionV2c),
                SnmpCodec.Tlv(TagOctetString, Encoding.ASCII.GetBytes(community)),
                pdu));
        }

        // 값 인코딩 도우미(테스트/시뮬레이터용): INTEGER 본문, OID 본문.
        public static byte[] IntegerContent(long value)
        {
            byte[] tlv = SnmpCodec.EncodeInteger(value);
            return tlv.AsSpan(2).ToArray(); // 길이 < 128 이므로 헤더 2바이트
        }

        public static byte[] OidContent(string oid)
        {
            byte[] tlv = SnmpCodec.EncodeOid(oid);
            int pos = 1;
            int len = ReadLength(tlv, ref pos);
            return len < 0 ? Array.Empty<byte>() : tlv.AsSpan(pos, len).ToArray();
        }

        // ---- 디코딩 ----

        public static bool TryParse(byte[]? data, out Pdu pdu)
        {
            pdu = new Pdu();
            if (data == null) return false;
            try
            {
                int pos = 0;
                if (!ReadHeader(data, ref pos, data.Length, out byte tag, out int len) || tag != TagSequence) return false;
                int end = pos + len;

                if (!ReadInt(data, ref pos, end, out pdu.Version)) return false;
                if (!ReadHeader(data, ref pos, end, out tag, out len) || tag != TagOctetString) return false;
                pdu.Community = Encoding.ASCII.GetString(data, pos, len);
                pos += len;

                if (!ReadHeader(data, ref pos, end, out tag, out len) || (tag & 0xE0) != 0xA0) return false;
                pdu.Type = tag;
                int pduEnd = pos + len;

                if (!ReadInt(data, ref pos, pduEnd, out pdu.RequestId)) return false;
                if (!ReadInt(data, ref pos, pduEnd, out pdu.ErrorStatus)) return false;
                if (!ReadInt(data, ref pos, pduEnd, out pdu.ErrorIndex)) return false;

                if (!ReadHeader(data, ref pos, pduEnd, out tag, out len) || tag != TagSequence) return false;
                int listEnd = pos + len;
                while (pos < listEnd)
                {
                    if (!ReadHeader(data, ref pos, listEnd, out tag, out len) || tag != TagSequence) return false;
                    int vbEnd = pos + len;
                    if (!ReadHeader(data, ref pos, vbEnd, out tag, out len) || tag != TagOid) return false;
                    string oid = SnmpCodec.DecodeOid(data, pos, len);
                    pos += len;
                    if (!ReadHeader(data, ref pos, vbEnd, out tag, out len)) return false;
                    pdu.VarBinds.Add(new VarBind(oid, tag, data.AsSpan(pos, len).ToArray()));
                    pos = vbEnd;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        // 태그와 원시 바이트를 표시용 문자열로. OCTET STRING은 출력 가능하면 텍스트, 6바이트 바이너리는 MAC 표기, 그 외 바이너리는 hex.
        public static string FormatText(byte tag, byte[] raw)
        {
            switch (tag)
            {
                case TagInteger:
                    return DecodeSigned(raw).ToString(CultureInfo.InvariantCulture);
                case TagCounter32:
                case TagGauge32:
                case TagTimeTicks:
                case TagCounter64:
                    return DecodeUnsigned(raw).ToString(CultureInfo.InvariantCulture);
                case TagOctetString:
                    return FormatOctetString(raw);
                case TagOid:
                    return SnmpCodec.DecodeOid(raw, 0, raw.Length);
                case TagIpAddress:
                    return raw.Length == 4 ? $"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}" : ToHex(raw);
                default:
                    return "";
            }
        }

        public static bool IsPrintable(ReadOnlySpan<byte> raw)
        {
            if (raw.Length == 0) return true;
            foreach (byte b in raw)
            {
                if ((b < 0x20 && b != '\t' && b != '\r' && b != '\n') || b == 0x7F) return false;
            }
            return true;
        }

        private static string FormatOctetString(byte[] raw)
        {
            // 끝의 NUL 패딩은 무시하고 판단한다(일부 장비가 ifDescr 뒤에 \0을 붙인다).
            int len = raw.Length;
            while (len > 0 && raw[len - 1] == 0) len--;
            if (IsPrintable(raw.AsSpan(0, len)) && (len > 0 || raw.Length == 0))
                return Encoding.UTF8.GetString(raw, 0, len).Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();
            if (raw.Length == 6)
                return InfrastructureFacts.MacFromBytes(raw) ?? "00-00-00-00-00-00";
            return ToHex(raw);
        }

        public static string ToHex(ReadOnlySpan<byte> raw)
        {
            var sb = new StringBuilder(raw.Length * 3);
            for (int i = 0; i < raw.Length; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(raw[i].ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        public static long DecodeSigned(ReadOnlySpan<byte> raw)
        {
            if (raw.Length == 0 || raw.Length > 8) return 0;
            long v = (raw[0] & 0x80) != 0 ? -1 : 0;
            foreach (byte b in raw) v = (v << 8) | b;
            return v;
        }

        public static ulong DecodeUnsigned(ReadOnlySpan<byte> raw)
        {
            // Counter64는 최상위 비트 때문에 앞에 0x00이 붙어 9바이트가 될 수 있다.
            if (raw.Length == 9 && raw[0] == 0) raw = raw.Slice(1);
            if (raw.Length == 0 || raw.Length > 8) return 0;
            ulong v = 0;
            foreach (byte b in raw) v = (v << 8) | b;
            return v;
        }

        // ---- 저수준 읽기 ----

        private static bool ReadHeader(byte[] data, ref int pos, int limit, out byte tag, out int len)
        {
            tag = 0; len = 0;
            if (limit > data.Length) limit = data.Length;
            if (pos + 2 > limit) return false;
            tag = data[pos++];
            len = ReadLength(data, ref pos);
            return len >= 0 && pos + len <= limit;
        }

        private static int ReadLength(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return -1;
            int first = data[pos++];
            if (first < 0x80) return first;
            int n = first & 0x7F;
            if (n == 0 || n > 3 || pos + n > data.Length) return -1;
            int len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | data[pos++];
            return len;
        }

        private static bool ReadInt(byte[] data, ref int pos, int limit, out int value)
        {
            value = 0;
            if (!ReadHeader(data, ref pos, limit, out byte tag, out int len) || tag != TagInteger || len > 4) return false;
            value = (int)DecodeSigned(data.AsSpan(pos, len));
            pos += len;
            return true;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] p in parts) total += p.Length;
            var result = new byte[total];
            int pos = 0;
            foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, result, pos, p.Length); pos += p.Length; }
            return result;
        }
    }

    // 점 표기 OID 비교/부분트리 판정 도우미. 숫자 arc 단위로 비교한다.
    internal static class OidUtil
    {
        public static string Normalize(string oid) => oid.Trim().TrimStart('.');

        public static bool TryParse(string oid, out long[] arcs)
        {
            string[] parts = Normalize(oid).Split('.', StringSplitOptions.RemoveEmptyEntries);
            arcs = new long[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (!long.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out arcs[i])) return false;
            }
            return arcs.Length > 0;
        }

        public static int Compare(string a, string b)
        {
            if (!TryParse(a, out long[] x) || !TryParse(b, out long[] y)) return string.CompareOrdinal(a, b);
            int n = Math.Min(x.Length, y.Length);
            for (int i = 0; i < n; i++)
            {
                if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
            }
            return x.Length.CompareTo(y.Length);
        }

        // oid가 base와 같거나 그 아래인가.
        public static bool IsUnder(string oid, string baseOid)
        {
            string o = Normalize(oid), b = Normalize(baseOid);
            return o == b || o.StartsWith(b + ".", StringComparison.Ordinal);
        }

        // base 아래의 나머지 arc들. base 아래가 아니면 null.
        public static long[]? Suffix(string oid, string baseOid)
        {
            string o = Normalize(oid), b = Normalize(baseOid);
            if (!o.StartsWith(b + ".", StringComparison.Ordinal)) return null;
            return TryParse(o.Substring(b.Length + 1), out long[] arcs) ? arcs : null;
        }
    }
}
