namespace NetworkScanner.Platform
{
    // OS별 ARP 테이블 조회기. 외부 명령(arp 등)에 의존하지 않고 네이티브 API로 MAC을 읽는다.
    public interface IArpResolver
    {
        // IPv4 주소의 MAC을 "AA-BB-CC-DD-EE-FF"(대문자·하이픈) 형식으로 반환한다.
        // 미확인/불완전(incomplete) 항목이거나 전부 0인 MAC이면 null. 절대 예외를 던지지 않는다.
        string? Resolve(string ipv4);
    }

    // 지원하지 않는 OS용 — 항상 null.
    public sealed class NullArpResolver : IArpResolver
    {
        public string? Resolve(string ipv4) => null;
    }

    // 각 구현체가 공유하는 MAC 형식 유틸리티.
    internal static class MacFormat
    {
        // 6바이트 → "AA-BB-CC-DD-EE-FF". 전부 0이면 null.
        public static string? FromBytes(ReadOnlySpan<byte> mac)
        {
            if (mac.Length != 6) return null;

            bool allZero = true;
            foreach (byte b in mac)
            {
                if (b != 0) { allZero = false; break; }
            }
            if (allZero) return null;

            return string.Create(17, mac.ToArray(), static (span, bytes) =>
            {
                const string hex = "0123456789ABCDEF";
                int pos = 0;
                for (int i = 0; i < bytes.Length; i++)
                {
                    if (i > 0) span[pos++] = '-';
                    span[pos++] = hex[bytes[i] >> 4];
                    span[pos++] = hex[bytes[i] & 0xF];
                }
            });
        }

        // "0:23:aa:3a:82:ba" / "00-23-AA-.." 같은 문자열 → "00-23-AA-3A-82-BA". 옥텟 수가 6이 아니거나 전부 0이면 null.
        public static string? FromText(string raw)
        {
            string[] octets = raw.Split(':', '-');
            if (octets.Length != 6) return null;

            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                if (!byte.TryParse(octets[i], System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                    return null;
            }
            return FromBytes(bytes);
        }
    }
}
