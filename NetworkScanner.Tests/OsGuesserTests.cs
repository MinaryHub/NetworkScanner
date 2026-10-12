using NetworkScanner;

namespace NetworkScanner.Tests
{
    public class OsGuessHeuristicsTests
    {
        [Theory]
        [InlineData(0, "Apple, Inc.", "", "iPad-16", "", "iPadOS")]
        [InlineData(64, "Apple, Inc.", "22/", "MacBook-Pro", "", "macOS")]
        [InlineData(64, "Apple, Inc.", "", "", "", "iOS/macOS")]
        [InlineData(128, "", "135/445/3389/", "", "", "Windows")]
        [InlineData(64, "Raspberry Pi Trading Ltd", "22/", "", "", "Linux")]
        [InlineData(64, "", "22/", "", "", "Linux/Unix")]
        [InlineData(64, "", "9100/", "", "", "Printer firmware")]
        [InlineData(0, "", "", "", "", "")]
        [InlineData(255, "HFR, Inc.", "80/443/", "", "", "Network device")]
        [InlineData(64, "Samsung Electronics", "", "", "Linux (Ubuntu 22.04)", "Linux (Ubuntu 22.04)")]
        [InlineData(0, "", "62078/", "", "", "iOS")]
        [InlineData(0, "", "", "DESKTOP-K2V9", "", "Windows")]
        public void Guess_UsesHintsVendorNamePortsThenTtl(int ttl, string vendor, string ports, string name, string hint, string expected)
        {
            Localization.Current = Localization.English;
            Assert.Equal(expected, OsGuesser.Guess(ttl, vendor, ports, name, hint));
        }

        [Fact]
        public void IPInfo_OsGuess_PrefersIdentityHint()
        {
            var info = new IPInfo { Ttl = 128, Vendor = "Dell Inc.", Ports = "22/", OsHint = "Cisco IOS" };
            Assert.Equal("Cisco IOS", info.OsGuess);
            info.OsHint = "";
            Assert.Equal("Windows", info.OsGuess); // 128 TTL, 22만 열림(445 없음) → TTL 규칙
        }
    }
}
