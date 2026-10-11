using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NetworkScanner.Reports;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;
using Xunit;

namespace NetworkScanner.Tests
{
    // PDF 리포트는 네트워크 없이 순수 메모리에서 만들어지므로 어떤 OS에서나 실행된다.
    public class PdfReportTests
    {
        private static List<IPInfo> MakeRows(int count, bool korean)
        {
            var rows = new List<IPInfo>();
            for (int i = 0; i < count; i++)
            {
                bool alive = i % 4 != 3;
                bool risky = alive && i % 7 == 0;
                rows.Add(new IPInfo
                {
                    Ip = $"10.0.{i / 250 + 1}.{i % 250 + 1}",
                    Alive = alive,
                    HasProhibitedPort = risky,
                    Ports = alive ? (risky ? "22/80/443/31337" : "22/80/443") : "",
                    SystemName = korean ? $"사무실-PC-{i:D2} 개발팀 노트북" : $"office-pc-{i:D2} dev laptop",
                    Description = korean ? "비고 테스트" : "note test",
                    Macaddr = alive ? $"00:1A:2B:{i:X2}:4D:5E" : "",
                    Vendor = korean ? "삼성전자 Samsung Electronics Co., Ltd." : "Samsung Electronics Co., Ltd.",
                    RountTime = alive ? (i % 50).ToString() : "",
                    Service = alive ? "HTTP: nginx/1.24, SSH-2.0-OpenSSH_9.6 very long banner text here" : "",
                    Ttl = alive ? 64 : 0,
                });
            }
            return rows;
        }

        private static byte[] BuildIn(string language, PdfReportOptions? options = null, int rows = 60)
        {
            string previous = Localization.Current;
            Localization.Current = language;
            try
            {
                return PdfReport.Build(MakeRows(rows, language == Localization.Korean), "테스트-시스템 TestSystem", "2026-10-11 09:30:00", options);
            }
            finally
            {
                Localization.Current = previous;
            }
        }

        private static int PageCount(byte[] pdf)
        {
            using var stream = new MemoryStream(pdf);
            using PdfDocument doc = PdfReader.Open(stream, PdfDocumentOpenMode.Import);
            return doc.PageCount;
        }

        [Theory]
        [InlineData(Localization.Korean)]
        [InlineData(Localization.English)]
        public void Build_60Rows_ProducesMultiPagePdf(string language)
        {
            byte[] pdf = BuildIn(language);

            Assert.StartsWith("%PDF-", Encoding.ASCII.GetString(pdf, 0, 5));
            Assert.True(pdf.Length > 10 * 1024, $"PDF too small: {pdf.Length} bytes");
            Assert.True(PageCount(pdf) >= 2, "60 rows should paginate onto at least two pages");

            // 나눔고딕 서브셋이 실제로 임베드되었는지(폰트 이름이 문서에 남는다)
            Assert.Contains("NanumGothic", Encoding.Latin1.GetString(pdf));
        }

        [Fact]
        public void Build_Portrait_UsesPortraitPage()
        {
            byte[] pdf = BuildIn(Localization.English, new PdfReportOptions { Landscape = false });
            using var stream = new MemoryStream(pdf);
            using PdfDocument doc = PdfReader.Open(stream, PdfDocumentOpenMode.Import);
            PdfPage page = doc.Pages[0];
            Assert.True(page.Width.Point < page.Height.Point);

            byte[] landscape = BuildIn(Localization.English);
            using var stream2 = new MemoryStream(landscape);
            using PdfDocument doc2 = PdfReader.Open(stream2, PdfDocumentOpenMode.Import);
            Assert.True(doc2.Pages[0].Width.Point > doc2.Pages[0].Height.Point);
        }

        [Fact]
        public void Build_WithChangesAndSubtitle_Succeeds()
        {
            var changes = new List<ScanChange>
            {
                new(ScanChangeType.NewHost, "10.0.1.5", "새 장비"),
                new(ScanChangeType.MacChanged, "10.0.1.6", "00:11:22:33:44:55 → 66:77:88:99:AA:BB"),
                new(ScanChangeType.ProhibitedPort, "10.0.1.7", "22/31337"),
                new(ScanChangeType.NewOpenPort, "10.0.1.8", "8080"),
                new(ScanChangeType.HostOffline, "10.0.1.9", "응답 없음"),
            };
            var options = new PdfReportOptions { Changes = changes, Subtitle = "10.0.1.1 - 10.0.1.254 (스캔 범위)" };

            byte[] ko = BuildIn(Localization.Korean, options);
            byte[] en = BuildIn(Localization.English, options);

            Assert.True(PageCount(ko) >= 2);
            Assert.True(PageCount(en) >= 2);
            // 변화 섹션만큼 더 길어진다.
            Assert.True(ko.Length > BuildIn(Localization.Korean).Length);
        }

        [Fact]
        public void Build_EmptyList_StillProducesOnePage()
        {
            byte[] pdf = PdfReport.Build(Array.Empty<IPInfo>(), "sys", "now");
            Assert.StartsWith("%PDF-", Encoding.ASCII.GetString(pdf, 0, 5));
            Assert.Equal(1, PageCount(pdf));
        }

        [Fact]
        public void EmbeddedFontResources_Exist()
        {
            string[] names = typeof(PdfReport).Assembly.GetManifestResourceNames();
            Assert.Contains("NetworkScanner.Fonts.NanumGothic.ttf", names);
            Assert.Contains("NetworkScanner.Fonts.NanumGothicBold.ttf", names);

            byte[]? regular = NanumFontResolver.Instance.GetFont("NanumGothic#R");
            byte[]? bold = NanumFontResolver.Instance.GetFont("NanumGothic#B");
            Assert.NotNull(regular);
            Assert.NotNull(bold);
            Assert.True(regular!.Length > 1_000_000);
            Assert.True(bold!.Length > 1_000_000);
            // TrueType 매직(0x00010000)
            Assert.Equal(new byte[] { 0, 1, 0, 0 }, regular.Take(4).ToArray());
        }

        [Fact]
        public void FontResolver_MapsBoldAndRegular()
        {
            var regular = NanumFontResolver.Instance.ResolveTypeface("Nanum Gothic", bold: false, italic: false);
            var bold = NanumFontResolver.Instance.ResolveTypeface("Nanum Gothic", bold: true, italic: false);
            Assert.NotNull(regular);
            Assert.NotNull(bold);
            Assert.NotEqual(regular!.FaceName, bold!.FaceName);
        }

        [Fact]
        public async Task SaveAsync_WritesFile()
        {
            string dir = Path.Combine(Path.GetTempPath(), "NetworkScannerPdfTests", Guid.NewGuid().ToString("N"));
            string path = Path.Combine(dir, "sub", "report.pdf");
            try
            {
                await PdfReport.SaveAsync(path, MakeRows(5, korean: true), "sys", "2026-10-11 10:00");
                Assert.True(File.Exists(path));
                byte[] bytes = await File.ReadAllBytesAsync(path);
                Assert.StartsWith("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
                Assert.Equal(1, PageCount(bytes));
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
            }
        }

        [Fact]
        public void SanitizeText_StripsUnsupportedCharacters()
        {
            Assert.Equal("! MAC", PdfReport.SanitizeText("⚠ MAC"));
            Assert.Equal("a b", PdfReport.SanitizeText("a\nb"));
            Assert.Equal("ok", PdfReport.SanitizeText("ok\U0001F600")); // 이모지(서로게이트 쌍) 제거
            Assert.Equal("", PdfReport.SanitizeText(null));
        }
    }
}
