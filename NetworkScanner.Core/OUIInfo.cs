using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NetworkScanner
{
    // MAC 주소 → 제조사. IEEE의 세 레지스트리를 모두 본다:
    //   MA-L(24비트, ouiinfo.ini = oui.txt), MA-M(28비트, ouiinfo-mam.ini = mam.txt), MA-S(36비트, ouiinfo-mas.ini = oui36.txt).
    // 작은 제조사는 MA-M/MA-S 블록만 가진 경우가 많아 MA-L만 보면 빈칸이 된다. 긴 블록부터(MA-S → MA-M → MA-L) 찾는다.
    // 두 번째 16진수의 비트1이 켜진 주소(x2/x6/xA/xE)는 로컬 관리(랜덤) MAC이라 제조사를 알 수 없고, 그 사실을 표시한다.
    public class OUIInfo
    {
        public static Action<string>? OnError { get; set; }

        public const string MalFileName = "ouiinfo.ini";
        public const string MamFileName = "ouiinfo-mam.ini";
        public const string MasFileName = "ouiinfo-mas.ini";

        private readonly Dictionary<string, string> _mal = new(StringComparer.OrdinalIgnoreCase);   // 6 hex
        private readonly Dictionary<string, string> _mam = new(StringComparer.OrdinalIgnoreCase);   // 7 hex
        private readonly Dictionary<string, string> _mas = new(StringComparer.OrdinalIgnoreCase);   // 9 hex

        public int Count => _mal.Count + _mam.Count + _mas.Count;

        public void LoadInfo()
        {
            LoadFile(MalFileName, _mal, 0, required: true);
            LoadFile(MamFileName, _mam, 1, required: false);
            LoadFile(MasFileName, _mas, 3, required: false);
        }

        // IEEE 텍스트 형식: "AB-CD-EF   (hex)  Vendor" 다음 줄 "123000-123FFF  (base 16)  Vendor".
        // MA-L은 (hex) 줄만으로 충분하고, MA-M/MA-S는 (base 16) 범위의 앞 extraHex 자리(1/3)를 접두어에 덧붙여 키를 만든다.
        private void LoadFile(string fileName, Dictionary<string, string> table, int extraHex, bool required)
        {
            string path = DataPaths.Resolve(fileName);
            if (!File.Exists(path))
            {
                if (required) OnError?.Invoke(string.Format(Localization.T("msg.store.loadfailed"), fileName, "not found"));
                return;
            }

            string? prefix = null, vendor = null;
            try
            {
                foreach (string line in File.ReadLines(path, Encoding.UTF8))
                {
                    int hex = line.IndexOf("(hex)", StringComparison.Ordinal);
                    if (hex > 0)
                    {
                        prefix = Normalize(line.Substring(0, hex));
                        vendor = line.Substring(hex + 5).Trim();
                        if (extraHex == 0 && prefix.Length == 6 && vendor.Length > 0) table[prefix] = vendor;
                        continue;
                    }

                    if (extraHex == 0 || prefix == null) continue;
                    int b16 = line.IndexOf("(base 16)", StringComparison.Ordinal);
                    if (b16 <= 0) continue;
                    string range = line.Substring(0, b16).Trim();
                    int dash = range.IndexOf('-');
                    string start = dash > 0 ? range.Substring(0, dash) : range;
                    if (start.Length >= extraHex && !string.IsNullOrEmpty(vendor))
                        table[prefix + start.Substring(0, extraHex).ToUpperInvariant()] = vendor;
                    prefix = null;
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(string.Format(Localization.T("msg.parse.skipped"), fileName, ex.Message));
            }
        }

        public string GetVender(string? mac)
        {
            if (!IsValidMac(mac)) return "";
            string hex = Normalize(mac!);
            if (hex.Length < 6) return "";

            if (hex.Length >= 9 && _mas.TryGetValue(hex.Substring(0, 9), out string? s)) return s;
            if (hex.Length >= 7 && _mam.TryGetValue(hex.Substring(0, 7), out string? m)) return m;
            if (_mal.TryGetValue(hex.Substring(0, 6), out string? l)) return l;

            return IsLocallyAdministered(hex) ? Localization.T("vendor.private") : "";
        }

        // 두 번째 16진수의 비트 1(0x02)이 켜져 있으면 로컬 관리 주소 — 폰/노트북의 랜덤 MAC, VM 등.
        public static bool IsLocallyAdministered(string macHex)
        {
            if (macHex.Length < 2) return false;
            return Uri.IsHexDigit(macHex[1]) && (Convert.ToInt32(macHex[1].ToString(), 16) & 0x2) != 0;
        }

        public bool IsValidMac(string? mac) => !string.IsNullOrEmpty(mac) && Normalize(mac).Length >= 6;

        private static string Normalize(string mac)
        {
            var sb = new StringBuilder(12);
            foreach (char c in mac)
                if (Uri.IsHexDigit(c)) sb.Append(char.ToUpperInvariant(c));
            return sb.ToString();
        }
    }
}
