using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace KetworkScanner.Discovery.Fingerprint
{
    // SMB2 NEGOTIATE / SESSION_SETUP 패킷 조립·해석(MS-SMB2 2.2.3~2.2.6)과 NetBIOS 세션 프레이밍(RFC 1002).
    // 서명·암호화는 다루지 않는다. NTLM CHALLENGE를 받는 데까지만 필요하다.
    internal static class Smb2Codec
    {
        public const int HeaderSize = 64;
        public const ushort CommandNegotiate = 0x0000;
        public const ushort CommandSessionSetup = 0x0001;
        public const uint StatusSuccess = 0x00000000;
        public const uint FlagServerToRedir = 0x00000001;

        public const ushort Dialect202 = 0x0202, Dialect210 = 0x0210, Dialect300 = 0x0300, Dialect302 = 0x0302, Dialect311 = 0x0311;
        public static readonly ushort[] Dialects = { Dialect202, Dialect210, Dialect300, Dialect302, Dialect311 };

        private static readonly byte[] ProtocolId = { 0xFE, (byte)'S', (byte)'M', (byte)'B' };
        private static readonly byte[] Smb1ProtocolId = { 0xFF, (byte)'S', (byte)'M', (byte)'B' };

        public readonly record struct Header(ushort Command, uint Status, uint Flags, ulong MessageId, ulong SessionId)
        {
            public bool IsResponse => (Flags & FlagServerToRedir) != 0;
        }

        public static string DialectName(ushort dialect) => dialect switch
        {
            Dialect202 => "SMB 2.0.2",
            Dialect210 => "SMB 2.1",
            Dialect300 => "SMB 3.0",
            Dialect302 => "SMB 3.0.2",
            Dialect311 => "SMB 3.1.1",
            0x02FF => "SMB 2.x",
            _ => $"SMB2 (0x{dialect:X4})",
        };

        // ---------- NetBIOS 세션 프레이밍 ----------

        public static byte[] Frame(byte[] smb)
        {
            var framed = new byte[4 + smb.Length];
            framed[0] = 0;
            framed[1] = (byte)(smb.Length >> 16);
            framed[2] = (byte)(smb.Length >> 8);
            framed[3] = (byte)smb.Length;
            Buffer.BlockCopy(smb, 0, framed, 4, smb.Length);
            return framed;
        }

        // 프레임 하나(본문만)를 읽는다. 끊기거나 길이가 비정상이면 null.
        public static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken ct, int maxLength = 1 << 20)
        {
            var head = new byte[4];
            if (!await ProbeTcp.ReadExactAsync(stream, head, 4, ct).ConfigureAwait(false)) return null;
            int length = (head[1] << 16) | (head[2] << 8) | head[3];
            if (length <= 0 || length > maxLength) return null;
            var body = new byte[length];
            if (!await ProbeTcp.ReadExactAsync(stream, body, length, ct).ConfigureAwait(false)) return null;
            return body;
        }

        // ---------- 헤더 ----------

        private static void WriteHeader(Span<byte> h, ushort command, uint status, uint flags, ushort creditCharge, ushort credits, ulong messageId, ulong sessionId)
        {
            h.Clear();
            ProtocolId.CopyTo(h);
            BinaryPrimitives.WriteUInt16LittleEndian(h.Slice(4), HeaderSize);
            BinaryPrimitives.WriteUInt16LittleEndian(h.Slice(6), creditCharge);
            BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(8), status);
            BinaryPrimitives.WriteUInt16LittleEndian(h.Slice(12), command);
            BinaryPrimitives.WriteUInt16LittleEndian(h.Slice(14), credits);
            BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(16), flags);
            BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(20), 0);           // NextCommand
            BinaryPrimitives.WriteUInt64LittleEndian(h.Slice(24), messageId);
            BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(32), 0x0000FEFF);  // Reserved(ProcessId)
            BinaryPrimitives.WriteUInt32LittleEndian(h.Slice(36), 0);           // TreeId
            BinaryPrimitives.WriteUInt64LittleEndian(h.Slice(40), sessionId);
            // 48..63 Signature = 0
        }

        public static bool TryParseHeader(ReadOnlySpan<byte> smb, out Header header)
        {
            header = default;
            if (smb.Length < HeaderSize || !smb.Slice(0, 4).SequenceEqual(ProtocolId)) return false;
            if (BinaryPrimitives.ReadUInt16LittleEndian(smb.Slice(4)) != HeaderSize) return false;
            header = new Header(
                BinaryPrimitives.ReadUInt16LittleEndian(smb.Slice(12)),
                BinaryPrimitives.ReadUInt32LittleEndian(smb.Slice(8)),
                BinaryPrimitives.ReadUInt32LittleEndian(smb.Slice(16)),
                BinaryPrimitives.ReadUInt64LittleEndian(smb.Slice(24)),
                BinaryPrimitives.ReadUInt64LittleEndian(smb.Slice(40)));
            return true;
        }

        // ---------- NEGOTIATE ----------

        // 3.1.1을 제안하므로 PREAUTH_INTEGRITY(필수)·ENCRYPTION 협상 컨텍스트를 붙인다. 결과는 NetBIOS 프레임 포함.
        public static byte[] BuildNegotiateRequest(Guid clientGuid, ulong messageId = 0)
        {
            const int bodyFixed = 36;
            int dialectsEnd = HeaderSize + bodyFixed + Dialects.Length * 2;      // 110
            int ctxOffset = Align8(dialectsEnd);                                  // 112
            const int preauthLen = 8 + 38;                                        // 헤더 8 + (count 2, saltLen 2, alg 2, salt 32)
            int encOffset = Align8(ctxOffset + preauthLen);                       // 160
            const int encLen = 8 + 6;                                             // 헤더 8 + (count 2, cipher 2×2)
            var msg = new byte[encOffset + encLen];
            Span<byte> s = msg;

            WriteHeader(s, CommandNegotiate, 0, 0, creditCharge: 0, credits: 1, messageId, 0);
            Span<byte> b = s.Slice(HeaderSize);
            BinaryPrimitives.WriteUInt16LittleEndian(b, bodyFixed);
            BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(2), (ushort)Dialects.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(4), 0x0001);          // SecurityMode: SIGNING_ENABLED
            BinaryPrimitives.WriteUInt32LittleEndian(b.Slice(8), 0x0000007F);      // Capabilities (DFS…ENCRYPTION)
            clientGuid.TryWriteBytes(b.Slice(12, 16));
            BinaryPrimitives.WriteUInt32LittleEndian(b.Slice(28), (uint)ctxOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(32), 2);               // NegotiateContextCount
            for (int i = 0; i < Dialects.Length; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(bodyFixed + i * 2), Dialects[i]);

            // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            Span<byte> c = s.Slice(ctxOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(c, 0x0001);
            BinaryPrimitives.WriteUInt16LittleEndian(c.Slice(2), 38);
            BinaryPrimitives.WriteUInt16LittleEndian(c.Slice(8), 1);                // HashAlgorithmCount
            BinaryPrimitives.WriteUInt16LittleEndian(c.Slice(10), 32);              // SaltLength
            BinaryPrimitives.WriteUInt16LittleEndian(c.Slice(12), 0x0001);          // SHA-512
            Random.Shared.NextBytes(c.Slice(14, 32));

            // SMB2_ENCRYPTION_CAPABILITIES
            Span<byte> e = s.Slice(encOffset);
            BinaryPrimitives.WriteUInt16LittleEndian(e, 0x0002);
            BinaryPrimitives.WriteUInt16LittleEndian(e.Slice(2), 6);
            BinaryPrimitives.WriteUInt16LittleEndian(e.Slice(8), 2);                // CipherCount
            BinaryPrimitives.WriteUInt16LittleEndian(e.Slice(10), 0x0002);          // AES-128-GCM
            BinaryPrimitives.WriteUInt16LittleEndian(e.Slice(12), 0x0001);          // AES-128-CCM

            return Frame(msg);
        }

        // 요청 검증용(테스트): 제안 다이얼렉트 목록을 돌려준다.
        public static bool TryParseNegotiateRequest(ReadOnlySpan<byte> smb, out ushort[] dialects)
        {
            dialects = Array.Empty<ushort>();
            if (!TryParseHeader(smb, out Header h) || h.Command != CommandNegotiate || h.IsResponse) return false;
            ReadOnlySpan<byte> b = smb.Slice(HeaderSize);
            if (b.Length < 36 || BinaryPrimitives.ReadUInt16LittleEndian(b) != 36) return false;
            int count = BinaryPrimitives.ReadUInt16LittleEndian(b.Slice(2));
            if (count <= 0 || b.Length < 36 + count * 2) return false;
            dialects = new ushort[count];
            for (int i = 0; i < count; i++) dialects[i] = BinaryPrimitives.ReadUInt16LittleEndian(b.Slice(36 + i * 2));
            return true;
        }

        public static bool TryParseNegotiateResponse(ReadOnlySpan<byte> smb, out ushort dialect)
        {
            dialect = 0;
            if (!TryParseHeader(smb, out Header h) || h.Command != CommandNegotiate || !h.IsResponse) return false;
            if (h.Status != StatusSuccess) return false;
            ReadOnlySpan<byte> b = smb.Slice(HeaderSize);
            if (b.Length < 64 || BinaryPrimitives.ReadUInt16LittleEndian(b) != 65) return false;
            dialect = BinaryPrimitives.ReadUInt16LittleEndian(b.Slice(4));
            return true;
        }

        // ---------- SESSION_SETUP ----------

        public static byte[] BuildSessionSetupRequest(byte[] securityBlob, ulong messageId = 1)
        {
            const int bodyFixed = 24;
            var msg = new byte[HeaderSize + bodyFixed + securityBlob.Length];
            Span<byte> s = msg;
            WriteHeader(s, CommandSessionSetup, 0, 0, creditCharge: 1, credits: 1, messageId, 0);
            Span<byte> b = s.Slice(HeaderSize);
            BinaryPrimitives.WriteUInt16LittleEndian(b, 25);
            b[2] = 0;                                                               // Flags
            b[3] = 0x01;                                                            // SecurityMode: SIGNING_ENABLED
            BinaryPrimitives.WriteUInt32LittleEndian(b.Slice(4), 0x00000001);       // Capabilities: DFS
            BinaryPrimitives.WriteUInt32LittleEndian(b.Slice(8), 0);                // Channel
            BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(12), (ushort)(HeaderSize + bodyFixed));
            BinaryPrimitives.WriteUInt16LittleEndian(b.Slice(14), (ushort)securityBlob.Length);
            BinaryPrimitives.WriteUInt64LittleEndian(b.Slice(16), 0);               // PreviousSessionId
            securityBlob.CopyTo(b.Slice(bodyFixed));
            return Frame(msg);
        }

        public static bool TryParseSessionSetupResponse(ReadOnlySpan<byte> smb, out uint status, out byte[] securityBlob)
        {
            status = 0;
            securityBlob = Array.Empty<byte>();
            if (!TryParseHeader(smb, out Header h) || h.Command != CommandSessionSetup || !h.IsResponse) return false;
            status = h.Status;
            ReadOnlySpan<byte> b = smb.Slice(HeaderSize);
            if (b.Length < 8 || BinaryPrimitives.ReadUInt16LittleEndian(b) != 9) return false;
            int offset = BinaryPrimitives.ReadUInt16LittleEndian(b.Slice(4));
            int length = BinaryPrimitives.ReadUInt16LittleEndian(b.Slice(6));
            if (length == 0) return true;
            if (offset < HeaderSize || offset + length > smb.Length) return false;
            securityBlob = smb.Slice(offset, length).ToArray();
            return true;
        }

        // ---------- SMB1(CIFS) NEGOTIATE: SMB2를 모르는 구형 서버 판별용 ----------

        public const byte Smb1CommandNegotiate = 0x72;
        private const string Smb1DialectNtLm = "NT LM 0.12";

        public static byte[] BuildSmb1NegotiateRequest()
        {
            byte[] dialect = System.Text.Encoding.ASCII.GetBytes(Smb1DialectNtLm);
            int byteCount = 1 + dialect.Length + 1;                                 // 0x02 + 문자열 + NUL
            var msg = new byte[32 + 1 + 2 + byteCount];
            Span<byte> s = msg;
            Smb1ProtocolId.CopyTo(s);
            s[4] = Smb1CommandNegotiate;
            s[9] = 0x18;                                                            // Flags: CASE_INSENSITIVE | CANONICALIZED_PATHS
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(10), 0xC853);          // Flags2: UNICODE|NT_STATUS|EXT_SEC|LONG_NAMES…
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(26), 0xFEFF);          // PIDLow
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(30), 1);               // MID
            s[32] = 0;                                                              // WordCount
            BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(33), (ushort)byteCount);
            s[35] = 0x02;
            dialect.CopyTo(s.Slice(36));
            return Frame(msg);
        }

        // 응답 헤더가 SMB1이고 상태가 성공이며 선택된 다이얼렉트가 있으면 true.
        public static bool TryParseSmb1NegotiateResponse(ReadOnlySpan<byte> smb, out int dialectIndex)
        {
            dialectIndex = -1;
            if (smb.Length < 37 || !smb.Slice(0, 4).SequenceEqual(Smb1ProtocolId)) return false;
            if (smb[4] != Smb1CommandNegotiate || (smb[9] & 0x80) == 0) return false;
            if (BinaryPrimitives.ReadUInt32LittleEndian(smb.Slice(5)) != 0) return false;
            int wordCount = smb[32];
            if (wordCount < 1) return false;
            dialectIndex = BinaryPrimitives.ReadUInt16LittleEndian(smb.Slice(33));
            return dialectIndex != 0xFFFF;
        }

        private static int Align8(int v) => (v + 7) & ~7;
    }
}
