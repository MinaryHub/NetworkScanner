using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace NetworkScanner.Discovery
{
    // SNMP v1/v2c 메시지의 최소 BER 인코더/디코더. GetRequest 생성과 GetResponse 파싱만 다룬다.
    internal static class SnmpCodec
    {
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
        public const byte PduGetRequest = 0xA0;
        public const byte PduGetResponse = 0xA2;

        public const int VersionV2c = 1;

        // 디코딩된 메시지. VarBinds의 값은 표시용 문자열(정수→10진, OID→점 표기, 문자열→UTF-8 또는 hex).
        public sealed class Message
        {
            public int Version;
            public string Community = "";
            public byte PduType;
            public int RequestId;
            public int ErrorStatus;
            public int ErrorIndex;
            public List<(string Oid, byte Tag, string? Value)> VarBinds = new();
        }

        public static byte[] BuildGetRequest(string community, int requestId, string[] oids)
        {
            var varbinds = new List<byte>();
            foreach (string oid in oids)
                varbinds.AddRange(Tlv(TagSequence, Concat(EncodeOid(oid), Tlv(TagNull, Array.Empty<byte>()))));
            return BuildMessage(community, PduGetRequest, requestId, 0, 0, varbinds.ToArray());
        }

        // 테스트/시뮬레이터용 GetResponse 생성. value가 null이면 noSuchObject로 응답한다.
        public static byte[] BuildGetResponse(string community, int requestId, IEnumerable<(string Oid, byte Tag, string? Value)> varbinds)
        {
            var list = new List<byte>();
            foreach (var (oid, tag, value) in varbinds)
            {
                byte[] encoded = value == null
                    ? Tlv(TagNoSuchObject, Array.Empty<byte>())
                    : tag switch
                    {
                        TagInteger => EncodeInteger(int.Parse(value, CultureInfo.InvariantCulture)),
                        TagOid => EncodeOid(value),
                        _ => Tlv(tag, Encoding.UTF8.GetBytes(value)),
                    };
                list.AddRange(Tlv(TagSequence, Concat(EncodeOid(oid), encoded)));
            }
            return BuildMessage(community, PduGetResponse, requestId, 0, 0, list.ToArray());
        }

        private static byte[] BuildMessage(string community, byte pduType, int requestId, int errorStatus, int errorIndex, byte[] varbinds)
        {
            byte[] pdu = Tlv(pduType, Concat(
                EncodeInteger(requestId),
                EncodeInteger(errorStatus),
                EncodeInteger(errorIndex),
                Tlv(TagSequence, varbinds)));
            return Tlv(TagSequence, Concat(
                EncodeInteger(VersionV2c),
                Tlv(TagOctetString, Encoding.ASCII.GetBytes(community)),
                pdu));
        }

        // GetResponse만 받아들인다. errorStatus != 0이면 values는 비고 false.
        public static bool TryParseResponse(byte[] data, out int requestId, out Dictionary<string, string> values)
        {
            requestId = 0;
            values = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!TryParseMessage(data, out Message? msg) || msg.PduType != PduGetResponse) return false;
            requestId = msg.RequestId;
            if (msg.ErrorStatus != 0) return false;
            foreach (var (oid, _, value) in msg.VarBinds)
            {
                if (value != null && !values.ContainsKey(oid)) values[oid] = value;
            }
            return true;
        }

        public static bool TryParseMessage(byte[] data, out Message message)
        {
            message = new Message();
            try
            {
                int pos = 0;
                if (!ReadHeader(data, ref pos, out byte tag, out int len) || tag != TagSequence) return false;
                int end = pos + len;
                if (end > data.Length) return false;

                if (!ReadInteger(data, ref pos, end, out message.Version)) return false;
                if (!ReadHeader(data, ref pos, out tag, out len) || tag != TagOctetString || pos + len > end) return false;
                message.Community = Encoding.ASCII.GetString(data, pos, len);
                pos += len;

                if (!ReadHeader(data, ref pos, out tag, out len) || (tag & 0xE0) != 0xA0 || pos + len > end) return false;
                message.PduType = tag;
                int pduEnd = pos + len;

                if (!ReadInteger(data, ref pos, pduEnd, out message.RequestId)) return false;
                if (!ReadInteger(data, ref pos, pduEnd, out message.ErrorStatus)) return false;
                if (!ReadInteger(data, ref pos, pduEnd, out message.ErrorIndex)) return false;

                if (!ReadHeader(data, ref pos, out tag, out len) || tag != TagSequence || pos + len > pduEnd) return false;
                int listEnd = pos + len;
                while (pos < listEnd)
                {
                    if (!ReadHeader(data, ref pos, out tag, out len) || tag != TagSequence || pos + len > listEnd) return false;
                    int vbEnd = pos + len;
                    if (!ReadHeader(data, ref pos, out tag, out len) || tag != TagOid || pos + len > vbEnd) return false;
                    string oid = DecodeOid(data, pos, len);
                    pos += len;
                    if (!ReadHeader(data, ref pos, out tag, out len) || pos + len > vbEnd) return false;
                    message.VarBinds.Add((oid, tag, DecodeValue(tag, data, pos, len)));
                    pos = vbEnd;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ---- 값 디코딩 ----

        private static string? DecodeValue(byte tag, byte[] data, int pos, int len)
        {
            switch (tag)
            {
                case TagInteger:
                case TagCounter32:
                case TagGauge32:
                case TagTimeTicks:
                case TagCounter64:
                    return DecodeIntegerValue(data, pos, len, signed: tag == TagInteger).ToString(CultureInfo.InvariantCulture);
                case TagOctetString:
                    return DecodeOctetString(data, pos, len);
                case TagOid:
                    return DecodeOid(data, pos, len);
                case TagIpAddress:
                    return len == 4 ? $"{data[pos]}.{data[pos + 1]}.{data[pos + 2]}.{data[pos + 3]}" : null;
                case TagNull:
                case TagNoSuchObject:
                case TagNoSuchInstance:
                case TagEndOfMibView:
                default:
                    return null;
            }
        }

        private static long DecodeIntegerValue(byte[] data, int pos, int len, bool signed)
        {
            if (len <= 0 || len > 8) return 0;
            long v = signed && (data[pos] & 0x80) != 0 ? -1 : 0;
            for (int i = 0; i < len; i++) v = (v << 8) | data[pos + i];
            return v;
        }

        // 제어 문자가 섞인 바이너리(MAC 등)는 hex로, 나머지는 UTF-8 텍스트로 돌려준다.
        private static string DecodeOctetString(byte[] data, int pos, int len)
        {
            bool printable = true;
            for (int i = 0; i < len; i++)
            {
                byte b = data[pos + i];
                if ((b < 0x20 && b != '\t' && b != '\r' && b != '\n') || b == 0x7F) { printable = false; break; }
            }
            if (!printable)
            {
                var sb = new StringBuilder(len * 3);
                for (int i = 0; i < len; i++)
                {
                    if (i > 0) sb.Append(':');
                    sb.Append(data[pos + i].ToString("x2", CultureInfo.InvariantCulture));
                }
                return sb.ToString();
            }
            return Encoding.UTF8.GetString(data, pos, len).Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Trim();
        }

        internal static string DecodeOid(byte[] data, int pos, int len)
        {
            var sb = new StringBuilder();
            int end = pos + len;
            long acc = 0;
            bool first = true;
            for (int i = pos; i < end; i++)
            {
                acc = (acc << 7) | (uint)(data[i] & 0x7F);
                if ((data[i] & 0x80) != 0) continue;
                if (first)
                {
                    long a = acc < 80 ? acc / 40 : 2;
                    long b = acc - a * 40;
                    sb.Append(a.ToString(CultureInfo.InvariantCulture)).Append('.').Append(b.ToString(CultureInfo.InvariantCulture));
                    first = false;
                }
                else
                {
                    sb.Append('.').Append(acc.ToString(CultureInfo.InvariantCulture));
                }
                acc = 0;
            }
            return sb.ToString();
        }

        // ---- 인코딩 ----

        internal static byte[] EncodeInteger(long value)
        {
            // 2의 보수 최소 바이트 수
            var bytes = new List<byte>();
            bool more = true;
            while (more)
            {
                byte b = (byte)(value & 0xFF);
                value >>= 8;
                bytes.Insert(0, b);
                more = !((value == 0 && (b & 0x80) == 0) || (value == -1 && (b & 0x80) != 0));
            }
            return Tlv(TagInteger, bytes.ToArray());
        }

        internal static byte[] EncodeOid(string oid)
        {
            string[] parts = oid.Trim().TrimStart('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ArgumentException("OID needs at least two arcs", nameof(oid));
            var body = new List<byte>();
            long a = long.Parse(parts[0], CultureInfo.InvariantCulture);
            long b = long.Parse(parts[1], CultureInfo.InvariantCulture);
            AppendBase128(body, a * 40 + b);
            for (int i = 2; i < parts.Length; i++)
                AppendBase128(body, long.Parse(parts[i], CultureInfo.InvariantCulture));
            return Tlv(TagOid, body.ToArray());
        }

        private static void AppendBase128(List<byte> dst, long value)
        {
            var tmp = new List<byte> { (byte)(value & 0x7F) };
            value >>= 7;
            while (value > 0)
            {
                tmp.Insert(0, (byte)((value & 0x7F) | 0x80));
                value >>= 7;
            }
            dst.AddRange(tmp);
        }

        internal static byte[] Tlv(byte tag, byte[] content)
        {
            var result = new List<byte>(content.Length + 4) { tag };
            int len = content.Length;
            if (len < 0x80) result.Add((byte)len);
            else if (len <= 0xFF) { result.Add(0x81); result.Add((byte)len); }
            else { result.Add(0x82); result.Add((byte)(len >> 8)); result.Add((byte)len); }
            result.AddRange(content);
            return result.ToArray();
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

        // ---- 저수준 읽기 ----

        private static bool ReadHeader(byte[] data, ref int pos, out byte tag, out int len)
        {
            tag = 0; len = 0;
            if (pos + 2 > data.Length) return false;
            tag = data[pos++];
            int first = data[pos++];
            if (first < 0x80) { len = first; }
            else
            {
                int n = first & 0x7F;
                if (n == 0 || n > 3 || pos + n > data.Length) return false;
                for (int i = 0; i < n; i++) len = (len << 8) | data[pos++];
            }
            return len >= 0 && pos + len <= data.Length;
        }

        private static bool ReadInteger(byte[] data, ref int pos, int end, out int value)
        {
            value = 0;
            if (!ReadHeader(data, ref pos, out byte tag, out int len) || tag != TagInteger || pos + len > end || len > 4) return false;
            value = (int)DecodeIntegerValue(data, pos, len, signed: true);
            pos += len;
            return true;
        }
    }
}
