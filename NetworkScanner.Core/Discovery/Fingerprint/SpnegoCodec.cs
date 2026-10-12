using System;
using System.Collections.Generic;

namespace NetworkScanner.Discovery.Fingerprint
{
    // SPNEGO(RFC 4178) / GSS-API(RFC 2743) 최소 구현: NTLMSSP 토큰을 negTokenInit에 싸고, negTokenResp에서 꺼낸다.
    internal static class SpnegoCodec
    {
        // 1.3.6.1.5.5.2
        public static readonly byte[] OidSpnego = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
        // 1.3.6.1.4.1.311.2.2.10
        public static readonly byte[] OidNtlmssp = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        private static readonly byte[] NtlmSignature = { (byte)'N', (byte)'T', (byte)'L', (byte)'M', (byte)'S', (byte)'S', (byte)'P', 0 };

        // GSS-API InitialContextToken{ SPNEGO OID, negTokenInit{ mechTypes=[NTLMSSP], mechToken } }
        public static byte[] WrapNegTokenInit(byte[] mechToken)
        {
            byte[] mechTypes = Tlv(0xa0, Tlv(0x30, Tlv(0x06, OidNtlmssp)));
            byte[] token = Tlv(0xa2, Tlv(0x04, mechToken));
            byte[] negTokenInit = Tlv(0xa0, Tlv(0x30, mechTypes, token));
            return Tlv(0x60, Tlv(0x06, OidSpnego), negTokenInit);
        }

        // negTokenResp{ negState, supportedMech=NTLMSSP, responseToken } (서버 역할: 테스트/루프백용)
        public static byte[] WrapNegTokenResp(byte[] responseToken, byte negState = 0x01 /* accept-incomplete */)
        {
            byte[] state = Tlv(0xa0, Tlv(0x0a, new[] { negState }));
            byte[] mech = Tlv(0xa1, Tlv(0x06, OidNtlmssp));
            byte[] token = Tlv(0xa2, Tlv(0x04, responseToken));
            return Tlv(0xa1, Tlv(0x30, state, mech, token));
        }

        // 보안 블롭 어디에 있든 "NTLMSSP\0" 서명부터 끝까지를 돌려준다(서버가 SPNEGO 없이 생 NTLM을 보내도 동작).
        // NTLM 메시지는 자체 오프셋/길이로 읽으므로 뒤에 DER 꼬리(mechListMIC 등)가 붙어 있어도 무해하다.
        public static byte[]? ExtractNtlmToken(ReadOnlySpan<byte> blob)
        {
            int i = blob.IndexOf(NtlmSignature);
            return i < 0 ? null : blob.Slice(i).ToArray();
        }

        // ---------- DER ----------

        public static byte[] Tlv(byte tag, params byte[][] contents)
        {
            int len = 0;
            foreach (byte[] c in contents) len += c.Length;
            byte[] lenBytes = EncodeLength(len);
            var buf = new byte[1 + lenBytes.Length + len];
            buf[0] = tag;
            lenBytes.CopyTo(buf, 1);
            int pos = 1 + lenBytes.Length;
            foreach (byte[] c in contents) { c.CopyTo(buf, pos); pos += c.Length; }
            return buf;
        }

        public static byte[] EncodeLength(int len)
        {
            if (len < 0x80) return new[] { (byte)len };
            var tmp = new List<byte>();
            for (int v = len; v > 0; v >>= 8) tmp.Insert(0, (byte)v);
            tmp.Insert(0, (byte)(0x80 | tmp.Count));
            return tmp.ToArray();
        }
    }
}
