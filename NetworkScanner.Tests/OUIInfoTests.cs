using NetworkScanner;

namespace NetworkScanner.Tests
{
    // OUIInfo.LoadInfo()는 프로세스 현재 디렉터리의 "ouiinfo.ini"를 읽는다.
    // 테스트 출력 디렉터리에 Fixtures/ouiinfo.ini가 같은 이름으로 복사되어 있다(csproj의 Link 설정 참고).
    public class OUIInfoTests
    {
        [Fact]
        public void GetVender_KnownMacPrefix_ReturnsOrganizationName()
        {
            var oui = new OUIInfo();
            oui.LoadInfo();

            string vendor = oui.GetVender("00-22-72-AA-BB-CC");

            Assert.Equal("American Micro-Fuel Device Corp.", vendor);
        }

        [Fact]
        public void GetVender_UnknownMacPrefix_ReturnsEmptyString()
        {
            var oui = new OUIInfo();
            oui.LoadInfo();

            string vendor = oui.GetVender("FC-FF-FF-AA-BB-CC"); // 범용(U/L 비트 0) 주소라 "랜덤 MAC" 표시 대상이 아님

            Assert.Equal("", vendor);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void IsValidMac_NullOrEmpty_ReturnsFalse(string? mac)
        {
            var oui = new OUIInfo();

            Assert.False(oui.IsValidMac(mac!));
        }

        [Fact]
        public void IsValidMac_NonEmptyString_ReturnsTrue()
        {
            var oui = new OUIInfo();

            Assert.True(oui.IsValidMac("00-22-72-AA-BB-CC"));
        }
    }
}

namespace NetworkScanner.Tests
{
    public class OUIRegistryTests
    {
        [Fact]
        public void LocallyAdministeredMac_IsLabelledAsPrivate()
        {
            Localization.Current = Localization.English;
            var oui = new OUIInfo();
            oui.LoadInfo();
            Assert.Equal(Localization.T("vendor.private"), oui.GetVender("7A-5E-35-7A-E0-BC"));
            Assert.Equal(Localization.T("vendor.private"), oui.GetVender("42:65:a2:35:a3:67"));
            Assert.True(OUIInfo.IsLocallyAdministered("7A5E357AE0BC"));
            Assert.False(OUIInfo.IsLocallyAdministered("0023AA3A82BA"));
        }

        [Fact]
        public void MamAndMasBlocks_AreLookedUpBeforeMal()
        {
            // 테스트 출력 폴더에 MA-M/MA-S 파일을 만들어 블록 단위 조회를 검증한다.
            string dir = System.IO.Directory.GetCurrentDirectory();
            System.IO.File.WriteAllText(System.IO.Path.Combine(dir, OUIInfo.MamFileName),
                "8C-1F-64   (hex)\t\tIEEE Registration Authority\n8C1F64000-8C1F64FFF     (base 16)\t\tIEEE Registration Authority\n\n" +
                "8C-1F-64   (hex)\t\tQUERCUS TECHNOLOGIES, S.L.\n9B9000-9B9FFF     (base 16)\t\tQUERCUS TECHNOLOGIES, S.L.\n");
            System.IO.File.WriteAllText(System.IO.Path.Combine(dir, OUIInfo.MasFileName),
                "70-B3-D5   (hex)\t\tACME Devices\nAFA000-AFAFFF     (base 16)\t\tACME Devices\n");
            try
            {
                var oui = new OUIInfo();
                oui.LoadInfo();
                Assert.Equal("QUERCUS TECHNOLOGIES, S.L.", oui.GetVender("8C-1F-64-9B-91-23"));
                Assert.Equal("ACME Devices", oui.GetVender("70-B3-D5-AF-A1-00"));
                Assert.Equal("", oui.GetVender("70-B3-D5-00-00-01")); // MA-S 블록 밖, MA-L에도 없음
            }
            finally
            {
                System.IO.File.Delete(System.IO.Path.Combine(dir, OUIInfo.MamFileName));
                System.IO.File.Delete(System.IO.Path.Combine(dir, OUIInfo.MasFileName));
            }
        }
    }
}
