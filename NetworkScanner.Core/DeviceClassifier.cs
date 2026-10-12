using System.Collections.Generic;

namespace NetworkScanner
{
    // 제조사(OUI 조회 결과)와 열린 포트를 힌트로 장비 종류를 대략 분류한다. 확실한 식별이 아니라 참고용 태그다.
    public static class DeviceClassifier
    {
        // 제조사명에 포함되면 해당 분류로 보는 키워드. 위쪽(더 구체적인 것)부터 검사한다.
        // 분류값은 지역화 키이며, 최종 표시 문자열은 Localization.T로 변환한다.
        private static readonly (string keyword, string categoryKey)[] VendorRules =
        {
            ("apple", "dev.apple"),
            ("samsung", "dev.samsung"),
            ("lg electronics", "dev.lg"),
            ("raspberry", "dev.raspberrypi"),
            ("intel", "dev.pclaptop"),
            ("dell", "dev.pclaptop"),
            ("asustek", "dev.pcnet"),
            ("giga-byte", "dev.pc"),
            ("micro-star", "dev.pc"),
            ("hewlett", "dev.printerpc"),
            ("canon", "dev.printer"),
            ("epson", "dev.printer"),
            ("brother", "dev.printer"),
            ("cisco", "dev.network"),
            ("tp-link", "dev.network"),
            ("netgear", "dev.network"),
            ("ubiquiti", "dev.network"),
            ("mikrotik", "dev.network"),
            ("d-link", "dev.network"),
            ("zyxel", "dev.network"),
            ("hangzhou hikvision", "dev.cctv"),
            ("dahua", "dev.cctv"),
            ("espressif", "dev.iot"),
            ("texas instrument", "dev.iot"),
            ("google", "dev.iotmedia"),
            ("amazon", "dev.iotmedia"),
            ("sonos", "dev.media"),
        };

        public static string Classify(string? vendor, string? openPorts)
        {
            string? key = ClassifyKey(vendor, openPorts);
            return key == null ? "" : Localization.T(key);
        }

        private static string? ClassifyKey(string? vendor, string? openPorts)
        {
            string v = (vendor ?? "").ToLowerInvariant();
            foreach (var (keyword, categoryKey) in VendorRules)
            {
                if (v.Contains(keyword)) return categoryKey;
            }

            // 제조사로 못 맞추면 열린 포트로 대략 추정한다.
            var ports = new HashSet<int>(Network.ProbeExtensions.ParsePorts(openPorts));
            if (ports.Contains(9100) || ports.Contains(515) || ports.Contains(631)) return "dev.printer";
            if (ports.Contains(554)) return "dev.cctv";
            if (ports.Contains(3389)) return "dev.windowspc";
            if (ports.Contains(445) || ports.Contains(139)) return "dev.winshare";
            if (ports.Contains(22)) return "dev.server";
            if (ports.Contains(80) || ports.Contains(443)) return "dev.web";

            return null;
        }
    }
}
