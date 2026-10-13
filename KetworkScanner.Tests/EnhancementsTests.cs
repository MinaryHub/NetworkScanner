using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class CidrTests
    {
        [Fact]
        public void TryParseCidr_Slash24_ReturnsUsableHostRange()
        {
            Assert.True(IPRangeUtil.TryParseCidr("192.168.1.0/24", out string start, out string end));
            Assert.Equal("192.168.1.1", start);
            Assert.Equal("192.168.1.254", end);
        }

        [Fact]
        public void TryParseCidr_Slash32_ReturnsSingleHost()
        {
            Assert.True(IPRangeUtil.TryParseCidr("10.0.0.5/32", out string start, out string end));
            Assert.Equal("10.0.0.5", start);
            Assert.Equal("10.0.0.5", end);
        }

        [Theory]
        [InlineData("not-a-cidr")]
        [InlineData("192.168.1.0")]
        [InlineData("192.168.1.0/33")]
        [InlineData("192.168.1.0/-1")]
        public void TryParseCidr_Invalid_ReturnsFalse(string input)
        {
            Assert.False(IPRangeUtil.TryParseCidr(input, out _, out _));
        }
    }

    public class DeviceClassifierTests
    {
        [Fact]
        public void Classify_ByVendorKeyword()
        {
            Assert.Equal(Localization.T("dev.apple"), DeviceClassifier.Classify("Apple, Inc.", ""));
            Assert.Equal(Localization.T("dev.network"), DeviceClassifier.Classify("Cisco Systems", ""));
        }

        [Fact]
        public void Classify_FallsBackToPortHeuristics_WhenVendorUnknown()
        {
            Assert.Equal(Localization.T("dev.printer"), DeviceClassifier.Classify("", "9100/"));
            Assert.Equal(Localization.T("dev.server"), DeviceClassifier.Classify("Unknown Co", "22/"));
        }

        [Fact]
        public void Classify_ReturnsEmpty_WhenNothingMatches()
        {
            Assert.Equal("", DeviceClassifier.Classify("Unknown Co", ""));
        }
    }

    public class ReportGeneratorTests
    {
        [Fact]
        public void BuildHtml_IncludesHostsCountsAndFlagsProhibited()
        {
            var items = new IPInfoList
            {
                new IPInfo { Ip = "10.0.0.1", Alive = true, Ports = "80/", Vendor = "Cisco Systems" },
                new IPInfo { Ip = "10.0.0.2", Alive = true, Ports = "31337/", HasProhibitedPort = true },
                new IPInfo { Ip = "10.0.0.3", Alive = false },
            };

            string html = ReportGenerator.BuildHtml(items, "TestSys", "2026-07-12 10:00:00");

            Assert.Contains("10.0.0.1", html);
            Assert.Contains("10.0.0.2", html);
            Assert.Contains("prohib", html);      // 위험 포트 행이 강조 클래스로 표시됨
            Assert.Contains("TestSys", html);
            Assert.Contains(Localization.T("dev.network"), html); // Cisco -> 종류 분류가 리포트에 반영됨
        }
    }
}

namespace KetworkScanner.Tests
{
    public class ColumnLayoutPersistenceTests
    {
        [Fact]
        public void SaveColumnLayout_RoundTripsWidths_WithoutClobberingOtherSettings()
        {
            // 사용자 프로필의 실제 설정을 건드리지 않도록 저장 위치를 테스트 폴더로 돌린다.
            UserDataPaths.OverrideRoot = System.IO.Directory.GetCurrentDirectory();
            string path = UserDataPaths.Resolve(AppSettingsStore.SettingFileName);
            string? backup = System.IO.File.Exists(path) ? System.IO.File.ReadAllText(path) : null;
            try
            {
                // 기존 설정을 저장해두고
                AppSettingsStore.SaveSettings(new AppSettingsData { SystemName = "keep-me", PortList = "22/80" });
                // 컬럼 너비만 갱신
                AppSettingsStore.SaveColumnLayout("90,140,160", "150,150,300");

                var loaded = AppSettingsStore.LoadSettings();
                Assert.Equal("90,140,160", loaded.IpListColumnWidths);
                Assert.Equal("150,150,300", loaded.IpRangeColumnWidths);
                Assert.Equal("keep-me", loaded.SystemName); // 다른 설정은 보존됨
                Assert.Equal("22/80", loaded.PortList);
            }
            finally
            {
                if (backup != null) System.IO.File.WriteAllText(path, backup);
                else System.IO.File.Delete(path);
            }
        }
    }
}
