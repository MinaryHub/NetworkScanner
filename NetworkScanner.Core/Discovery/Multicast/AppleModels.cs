using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace NetworkScanner.Discovery.Multicast
{
    // Apple 모델 식별자(MacBookPro18,3 / iPhone15,2 / J305AP …) → 제품명·장비 종류. 표에 없으면 접두어로 "Apple <family>"를 만든다.
    internal static class AppleModels
    {
        public sealed record Product(string Name, string DeviceType);

        private static readonly Dictionary<string, Product> Table = new(StringComparer.OrdinalIgnoreCase)
        {
            // MacBook Pro
            ["MacBookPro15,1"] = new("MacBook Pro (15-inch, 2018)", "computer"),
            ["MacBookPro15,2"] = new("MacBook Pro (13-inch, 2018)", "computer"),
            ["MacBookPro16,1"] = new("MacBook Pro (16-inch, 2019)", "computer"),
            ["MacBookPro16,2"] = new("MacBook Pro (13-inch, 2020)", "computer"),
            ["MacBookPro17,1"] = new("MacBook Pro (13-inch, M1, 2020)", "computer"),
            ["MacBookPro18,1"] = new("MacBook Pro (16-inch, 2021)", "computer"),
            ["MacBookPro18,2"] = new("MacBook Pro (16-inch, 2021)", "computer"),
            ["MacBookPro18,3"] = new("MacBook Pro (14-inch, 2021)", "computer"),
            ["MacBookPro18,4"] = new("MacBook Pro (14-inch, 2021)", "computer"),
            ["Mac14,5"] = new("MacBook Pro (14-inch, 2023)", "computer"),
            ["Mac14,9"] = new("MacBook Pro (14-inch, 2023)", "computer"),
            ["Mac14,6"] = new("MacBook Pro (16-inch, 2023)", "computer"),
            ["Mac14,10"] = new("MacBook Pro (16-inch, 2023)", "computer"),
            ["Mac14,7"] = new("MacBook Pro (13-inch, M2, 2022)", "computer"),
            ["Mac15,3"] = new("MacBook Pro (14-inch, M3, 2023)", "computer"),
            ["Mac15,6"] = new("MacBook Pro (14-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac15,8"] = new("MacBook Pro (14-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac15,10"] = new("MacBook Pro (14-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac15,7"] = new("MacBook Pro (16-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac15,9"] = new("MacBook Pro (16-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac15,11"] = new("MacBook Pro (16-inch, M3 Pro/Max, 2023)", "computer"),
            ["Mac16,1"] = new("MacBook Pro (14-inch, M4, 2024)", "computer"),
            ["Mac16,6"] = new("MacBook Pro (14-inch, M4 Pro/Max, 2024)", "computer"),
            ["Mac16,8"] = new("MacBook Pro (14-inch, M4 Pro/Max, 2024)", "computer"),
            ["Mac16,5"] = new("MacBook Pro (16-inch, M4 Pro/Max, 2024)", "computer"),
            ["Mac16,7"] = new("MacBook Pro (16-inch, M4 Pro/Max, 2024)", "computer"),
            // MacBook Air
            ["MacBookAir8,1"] = new("MacBook Air (Retina, 2018)", "computer"),
            ["MacBookAir9,1"] = new("MacBook Air (Retina, 2020)", "computer"),
            ["MacBookAir10,1"] = new("MacBook Air (M1, 2020)", "computer"),
            ["Mac14,2"] = new("MacBook Air (13-inch, M2, 2022)", "computer"),
            ["Mac14,15"] = new("MacBook Air (15-inch, M2, 2023)", "computer"),
            ["Mac15,12"] = new("MacBook Air (13-inch, M3, 2024)", "computer"),
            ["Mac15,13"] = new("MacBook Air (15-inch, M3, 2024)", "computer"),
            ["Mac16,12"] = new("MacBook Air (13-inch, M4, 2025)", "computer"),
            ["Mac16,13"] = new("MacBook Air (15-inch, M4, 2025)", "computer"),
            // Mac mini / Studio / Pro / iMac
            ["Macmini8,1"] = new("Mac mini (2018)", "computer"),
            ["Macmini9,1"] = new("Mac mini (M1, 2020)", "computer"),
            ["Mac14,3"] = new("Mac mini (M2, 2023)", "computer"),
            ["Mac14,12"] = new("Mac mini (M2 Pro, 2023)", "computer"),
            ["Mac16,10"] = new("Mac mini (M4, 2024)", "computer"),
            ["Mac16,11"] = new("Mac mini (M4 Pro, 2024)", "computer"),
            ["Mac13,1"] = new("Mac Studio (M1 Max, 2022)", "computer"),
            ["Mac13,2"] = new("Mac Studio (M1 Ultra, 2022)", "computer"),
            ["Mac14,13"] = new("Mac Studio (M2 Max, 2023)", "computer"),
            ["Mac14,14"] = new("Mac Studio (M2 Ultra, 2023)", "computer"),
            ["Mac15,14"] = new("Mac Studio (M4 Max, 2025)", "computer"),
            ["Mac16,9"] = new("Mac Studio (M3 Ultra, 2025)", "computer"),
            ["Mac14,8"] = new("Mac Pro (2023)", "computer"),
            ["MacPro7,1"] = new("Mac Pro (2019)", "computer"),
            ["iMac19,1"] = new("iMac (Retina 5K, 27-inch, 2019)", "computer"),
            ["iMac20,1"] = new("iMac (Retina 5K, 27-inch, 2020)", "computer"),
            ["iMac21,1"] = new("iMac (24-inch, M1, 2021)", "computer"),
            ["iMac21,2"] = new("iMac (24-inch, M1, 2021)", "computer"),
            ["Mac15,4"] = new("iMac (24-inch, M3, 2023)", "computer"),
            ["Mac15,5"] = new("iMac (24-inch, M3, 2023)", "computer"),
            ["Mac16,2"] = new("iMac (24-inch, M4, 2024)", "computer"),
            ["Mac16,3"] = new("iMac (24-inch, M4, 2024)", "computer"),
            // iPhone
            ["iPhone12,1"] = new("iPhone 11", "phone"),
            ["iPhone12,3"] = new("iPhone 11 Pro", "phone"),
            ["iPhone12,5"] = new("iPhone 11 Pro Max", "phone"),
            ["iPhone12,8"] = new("iPhone SE (2nd gen)", "phone"),
            ["iPhone13,1"] = new("iPhone 12 mini", "phone"),
            ["iPhone13,2"] = new("iPhone 12", "phone"),
            ["iPhone13,3"] = new("iPhone 12 Pro", "phone"),
            ["iPhone13,4"] = new("iPhone 12 Pro Max", "phone"),
            ["iPhone14,4"] = new("iPhone 13 mini", "phone"),
            ["iPhone14,5"] = new("iPhone 13", "phone"),
            ["iPhone14,2"] = new("iPhone 13 Pro", "phone"),
            ["iPhone14,3"] = new("iPhone 13 Pro Max", "phone"),
            ["iPhone14,6"] = new("iPhone SE (3rd gen)", "phone"),
            ["iPhone14,7"] = new("iPhone 14", "phone"),
            ["iPhone14,8"] = new("iPhone 14 Plus", "phone"),
            ["iPhone15,2"] = new("iPhone 14 Pro", "phone"),
            ["iPhone15,3"] = new("iPhone 14 Pro Max", "phone"),
            ["iPhone15,4"] = new("iPhone 15", "phone"),
            ["iPhone15,5"] = new("iPhone 15 Plus", "phone"),
            ["iPhone16,1"] = new("iPhone 15 Pro", "phone"),
            ["iPhone16,2"] = new("iPhone 15 Pro Max", "phone"),
            ["iPhone17,3"] = new("iPhone 16", "phone"),
            ["iPhone17,4"] = new("iPhone 16 Plus", "phone"),
            ["iPhone17,1"] = new("iPhone 16 Pro", "phone"),
            ["iPhone17,2"] = new("iPhone 16 Pro Max", "phone"),
            ["iPhone17,5"] = new("iPhone 16e", "phone"),
            // iPad
            ["iPad7,11"] = new("iPad (7th gen)", "tablet"),
            ["iPad7,12"] = new("iPad (7th gen)", "tablet"),
            ["iPad11,6"] = new("iPad (8th gen)", "tablet"),
            ["iPad11,7"] = new("iPad (8th gen)", "tablet"),
            ["iPad12,1"] = new("iPad (9th gen)", "tablet"),
            ["iPad12,2"] = new("iPad (9th gen)", "tablet"),
            ["iPad13,18"] = new("iPad (10th gen)", "tablet"),
            ["iPad13,19"] = new("iPad (10th gen)", "tablet"),
            ["iPad13,1"] = new("iPad Air (4th gen)", "tablet"),
            ["iPad13,2"] = new("iPad Air (4th gen)", "tablet"),
            ["iPad13,16"] = new("iPad Air (5th gen)", "tablet"),
            ["iPad13,17"] = new("iPad Air (5th gen)", "tablet"),
            ["iPad14,8"] = new("iPad Air 11-inch (M2)", "tablet"),
            ["iPad14,9"] = new("iPad Air 11-inch (M2)", "tablet"),
            ["iPad14,10"] = new("iPad Air 13-inch (M2)", "tablet"),
            ["iPad14,11"] = new("iPad Air 13-inch (M2)", "tablet"),
            ["iPad11,1"] = new("iPad mini (5th gen)", "tablet"),
            ["iPad11,2"] = new("iPad mini (5th gen)", "tablet"),
            ["iPad14,1"] = new("iPad mini (6th gen)", "tablet"),
            ["iPad14,2"] = new("iPad mini (6th gen)", "tablet"),
            ["iPad8,9"] = new("iPad Pro 11-inch (2nd gen)", "tablet"),
            ["iPad8,10"] = new("iPad Pro 11-inch (2nd gen)", "tablet"),
            ["iPad8,11"] = new("iPad Pro 12.9-inch (4th gen)", "tablet"),
            ["iPad8,12"] = new("iPad Pro 12.9-inch (4th gen)", "tablet"),
            ["iPad13,4"] = new("iPad Pro 11-inch (3rd gen)", "tablet"),
            ["iPad13,5"] = new("iPad Pro 11-inch (3rd gen)", "tablet"),
            ["iPad13,6"] = new("iPad Pro 11-inch (3rd gen)", "tablet"),
            ["iPad13,7"] = new("iPad Pro 11-inch (3rd gen)", "tablet"),
            ["iPad13,8"] = new("iPad Pro 12.9-inch (5th gen)", "tablet"),
            ["iPad13,9"] = new("iPad Pro 12.9-inch (5th gen)", "tablet"),
            ["iPad13,10"] = new("iPad Pro 12.9-inch (5th gen)", "tablet"),
            ["iPad13,11"] = new("iPad Pro 12.9-inch (5th gen)", "tablet"),
            ["iPad14,3"] = new("iPad Pro 11-inch (4th gen)", "tablet"),
            ["iPad14,4"] = new("iPad Pro 11-inch (4th gen)", "tablet"),
            ["iPad14,5"] = new("iPad Pro 12.9-inch (6th gen)", "tablet"),
            ["iPad14,6"] = new("iPad Pro 12.9-inch (6th gen)", "tablet"),
            ["iPad16,3"] = new("iPad Pro 11-inch (M4)", "tablet"),
            ["iPad16,4"] = new("iPad Pro 11-inch (M4)", "tablet"),
            ["iPad16,5"] = new("iPad Pro 13-inch (M4)", "tablet"),
            ["iPad16,6"] = new("iPad Pro 13-inch (M4)", "tablet"),
            // Apple TV (모델 식별자와 보드 식별자 J…AP 둘 다 쓰인다)
            ["AppleTV5,3"] = new("Apple TV HD", "media"),
            ["AppleTV6,2"] = new("Apple TV 4K (1st gen)", "media"),
            ["AppleTV11,1"] = new("Apple TV 4K (2nd gen)", "media"),
            ["AppleTV14,1"] = new("Apple TV 4K (3rd gen)", "media"),
            ["J42dAP"] = new("Apple TV HD", "media"),
            ["J105aAP"] = new("Apple TV 4K (1st gen)", "media"),
            ["J305AP"] = new("Apple TV 4K (2nd gen)", "media"),
            ["J255AP"] = new("Apple TV 4K (3rd gen)", "media"),
            // HomePod
            ["AudioAccessory1,1"] = new("HomePod", "media"),
            ["AudioAccessory1,2"] = new("HomePod", "media"),
            ["AudioAccessory5,1"] = new("HomePod mini", "media"),
            ["AudioAccessory6,1"] = new("HomePod (2nd gen)", "media"),
            ["B520AP"] = new("HomePod mini", "media"),
            ["B620AP"] = new("HomePod (2nd gen)", "media"),
            // Vision
            ["RealityDevice14,1"] = new("Apple Vision Pro", "wearable"),
        };

        // 표에 없을 때 접두어로 만드는 일반 이름.
        private static readonly (string Prefix, string Family, string DeviceType)[] Families =
        {
            ("MacBookPro", "MacBook Pro", "computer"), ("MacBookAir", "MacBook Air", "computer"), ("MacBook", "MacBook", "computer"),
            ("Macmini", "Mac mini", "computer"), ("MacPro", "Mac Pro", "computer"), ("MacStudio", "Mac Studio", "computer"),
            ("iMacPro", "iMac Pro", "computer"), ("iMac", "iMac", "computer"), ("Mac", "Mac", "computer"),
            ("iPhone", "iPhone", "phone"), ("iPad", "iPad", "tablet"), ("iPod", "iPod touch", "media"),
            ("AppleTV", "TV", "media"), ("AudioAccessory", "HomePod", "media"), ("Watch", "Watch", "wearable"),
            ("RealityDevice", "Vision Pro", "wearable"), ("AppleDisplay", "Studio Display", "display"),
        };

        private static readonly Regex AppleIdPattern = new(@"^(MacBookPro|MacBookAir|MacBook|Macmini|MacPro|MacStudio|iMacPro|iMac|Mac|iPhone|iPad|iPod|AppleTV|AudioAccessory|Watch|RealityDevice|AppleDisplay)\d+,\d+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex BoardIdPattern = new(@"^[A-Z]\d{2,3}[a-z]?AP$", RegexOptions.Compiled);

        // Apple 식별자로 보이면 true와 제품 정보를, 아니면 false를 돌려준다.
        public static bool TryDescribe(string? identifier, out Product product)
        {
            product = default!;
            if (string.IsNullOrWhiteSpace(identifier)) return false;
            string id = identifier.Trim();
            if (Table.TryGetValue(id, out Product? known)) { product = known; return true; }

            if (AppleIdPattern.IsMatch(id))
            {
                foreach (var (prefix, family, type) in Families)
                {
                    if (!id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
                    product = new Product("Apple " + family, type);
                    return true;
                }
            }
            if (BoardIdPattern.IsMatch(id))
            {
                // J…AP는 Apple TV, B…AP는 HomePod, 그 외 보드 ID는 종류를 단정하지 않는다.
                char c = char.ToUpperInvariant(id[0]);
                product = c switch
                {
                    'J' => new Product("Apple TV", "media"),
                    'B' => new Product("Apple HomePod", "media"),
                    _ => new Product("Apple device", "iot"),
                };
                return true;
            }
            return false;
        }

        // _device-info TXT의 osxvers(Darwin 메이저) → macOS 마케팅 버전.
        public static string? MapOsxVers(string? osxvers)
        {
            if (string.IsNullOrWhiteSpace(osxvers) || !int.TryParse(osxvers.Trim(), out int major)) return null;
            return major switch
            {
                16 => "10.12", 17 => "10.13", 18 => "10.14", 19 => "10.15",
                20 => "11", 21 => "12", 22 => "13", 23 => "14", 24 => "15", 25 => "26",
                _ => major > 25 ? (major + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) : null,
            };
        }
    }
}
