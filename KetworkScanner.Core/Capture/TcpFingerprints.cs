using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using KetworkScanner.Discovery;

namespace KetworkScanner.Capture
{
    // TCP SYN-ACK 한 개에서 뽑은 OS 핑거프린트 재료. OptionOrder는 "mss,nop,wscale,nop,nop,ts,sack,eol"처럼 옵션 종류의 순서.
    public sealed record TcpSignature(int Ttl, int WindowSize, int Mss, int WindowScale, bool SackOk, bool Timestamps, string OptionOrder)
    {
        // p0f 식 한 줄 표기: "64:65535:1460:6:1:1:mss,nop,wscale,nop,nop,ts,sack,eol"
        public override string ToString() =>
            string.Create(CultureInfo.InvariantCulture, $"{Ttl}:{WindowSize}:{Mss}:{WindowScale}:{(SackOk ? 1 : 0)}:{(Timestamps ? 1 : 0)}:{OptionOrder}");

        // TCP 헤더의 옵션 바이트(헤더 20바이트 이후, 데이터 오프셋까지)를 읽어 서명을 만든다.
        public static TcpSignature FromOptions(int ttl, int windowSize, ReadOnlySpan<byte> options)
        {
            int mss = 0, wscale = -1; bool sack = false, ts = false;
            var order = new StringBuilder();
            int pos = 0;
            void Add(string tok) { if (order.Length > 0) order.Append(','); order.Append(tok); }

            while (pos < options.Length)
            {
                byte kind = options[pos];
                if (kind == 0) { Add("eol"); break; }
                if (kind == 1) { Add("nop"); pos++; continue; }
                if (pos + 1 >= options.Length) break;
                int len = options[pos + 1];
                if (len < 2 || pos + len > options.Length) break;
                switch (kind)
                {
                    case 2: Add("mss"); if (len == 4) mss = (options[pos + 2] << 8) | options[pos + 3]; break;
                    case 3: Add("wscale"); if (len == 3) wscale = options[pos + 2]; break;
                    case 4: Add("sack"); sack = true; break;
                    case 5: Add("sackblk"); break;
                    case 8: Add("ts"); ts = true; break;
                    default: Add("opt" + kind.ToString(CultureInfo.InvariantCulture)); break;
                }
                pos += len;
            }
            return new TcpSignature(ttl, windowSize, mss, wscale, sack, ts, order.ToString());
        }
    }

    // p0f 축소판: SYN-ACK 서명 → OS 추정. 규칙은 위에서부터 첫 일치가 이긴다. 확신은 기본 Medium(TTL만으로 갈리는 건 Low).
    internal static class TcpFingerprints
    {
        public sealed record Result(string Os, Confidence Confidence, string Rule);

        private static readonly HashSet<int> LinuxWindows = new() { 5792, 14480, 14600, 26847, 28960, 29200, 42340, 64240, 65160, 65535 };
        private static readonly HashSet<int> WindowsWindows = new() { 8192, 16384, 64240, 65392, 65535 };

        public static Result? Match(TcpSignature s)
        {
            string o = s.OptionOrder;
            // 네트워크 장비(TTL 255)
            if (s.Ttl == 255 && s.WindowSize == 4128) return new Result("Cisco IOS", Confidence.Medium, "ttl255-win4128");
            if (s.Ttl > 128 && o == "mss" && s.WindowSize is 4128 or 4096 or 8192) return new Result("Cisco IOS", Confidence.Low, "ttl255-mss");

            // 옛 리눅스 2.4/2.6 기본 윈도 5840
            if (s.Ttl <= 64 && s.WindowSize == 5840) return new Result("Linux 2.6 (old)", Confidence.Medium, "ttl64-win5840");

            // Apple: mss,nop,wscale,nop,nop,ts,sack,eol (macOS/iOS 공통)
            if (s.Ttl <= 64 && (o == "mss,nop,wscale,nop,nop,ts,sack,eol" || o == "mss,nop,wscale,nop,nop,ts,sack"))
                return new Result("macOS/iOS", Confidence.Medium, "apple-opts");
            if (s.Ttl <= 64 && s.WindowSize == 65535 && o == "mss,nop,wscale,sack,eol")
                return new Result("macOS (legacy)", Confidence.Low, "apple-legacy-opts");

            // Linux: mss,sack,ts,nop,wscale
            if (s.Ttl <= 64 && o == "mss,sack,ts,nop,wscale")
                return new Result("Linux", LinuxWindows.Contains(s.WindowSize) ? Confidence.Medium : Confidence.Low, "linux-opts");
            if (s.Ttl <= 64 && o == "mss,nop,nop,sack,nop,wscale")
                return new Result("Linux (no timestamps)", Confidence.Low, "linux-nots-opts");

            // FreeBSD/pfSense: mss,nop,wscale,sack,ts
            if (s.Ttl <= 64 && o == "mss,nop,wscale,sack,ts") return new Result("FreeBSD", Confidence.Medium, "freebsd-opts");
            // OpenBSD: mss,nop,nop,sack,nop,wscale,nop,nop,ts (win 16384)
            if (s.Ttl <= 64 && o == "mss,nop,nop,sack,nop,wscale,nop,nop,ts") return new Result("OpenBSD", Confidence.Medium, "openbsd-opts");

            // Windows: TTL 128, mss,nop,wscale,nop,nop,sack (Vista+) / mss,nop,nop,sack (XP/2003)
            if (s.Ttl > 64 && s.Ttl <= 128)
            {
                if (o == "mss,nop,wscale,nop,nop,sack" || o == "mss,nop,wscale,sack")
                    return new Result("Windows", WindowsWindows.Contains(s.WindowSize) ? Confidence.Medium : Confidence.Low, "windows-opts");
                if (o == "mss,nop,nop,sack") return new Result("Windows XP/2003", Confidence.Medium, "windows-xp-opts");
                if (o == "mss,nop,wscale,nop,nop,ts,sack" || o == "mss,nop,wscale,sack,ts")
                    return new Result("Windows (timestamps on)", Confidence.Low, "windows-ts-opts");
                if (o == "mss") return new Result("Windows (legacy/embedded)", Confidence.Low, "ttl128-mss");
            }

            // 옵션이 MSS뿐인 TTL 64 장비: 임베디드 리눅스/RTOS
            if (s.Ttl <= 64 && o == "mss") return new Result("Linux/embedded", Confidence.Low, "ttl64-mss");
            if (s.Ttl <= 64 && o.Length == 0) return new Result("Embedded/RTOS", Confidence.Low, "ttl64-noopts");
            return null;
        }
    }
}
