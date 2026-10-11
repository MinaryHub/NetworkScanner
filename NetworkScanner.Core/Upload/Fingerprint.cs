using System;
using System.Security.Cryptography;
using System.Text;

namespace NetworkScanner.Upload
{
    // 인증서/호스트키 지문 비교 도우미. 설정에 적는 형식은 "AB:CD:..."(SHA-256 hex, 대소문자·구분자 무관)이며
    // SSH 쪽 관례인 "SHA256:<base64>"도 받아들인다.
    public static class Fingerprint
    {
        public static string Sha256Hex(byte[] data)
        {
            byte[] hash = SHA256.HashData(data);
            var sb = new StringBuilder(hash.Length * 3);
            for (int i = 0; i < hash.Length; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public static string Normalize(string value)
        {
            value = value.Trim();
            if (value.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
            {
                // OpenSSH 표기: 패딩 없는 base64
                string b64 = value.Substring(7).Trim();
                try
                {
                    byte[] bytes = Convert.FromBase64String(b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '='));
                    return ToHex(bytes);
                }
                catch { return value.ToUpperInvariant(); }
            }
            var sb = new StringBuilder();
            foreach (char c in value)
            {
                if (Uri.IsHexDigit(c)) sb.Append(char.ToUpperInvariant(c));
            }
            return sb.ToString();
        }

        public static bool Matches(string expected, string actualHex)
            => Normalize(expected) == Normalize(actualHex);

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }
}
