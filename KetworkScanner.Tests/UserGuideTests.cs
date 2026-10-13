using System.Linq;
using Xunit;

namespace KetworkScanner.Tests
{
    public class UserGuideTests
    {
        [Fact]
        public void Languages_MatchUiLanguages_EnglishFirstAsDefault()
        {
            var codes = UserGuide.Languages.Select(l => l.Code).ToArray();
            Assert.Equal(new[] { Localization.English, Localization.Korean }, codes);
        }

        [Fact]
        public void GetSections_AllLanguages_HaveSameStructureAndNoEmptyText()
        {
            int expected = UserGuide.GetSections("en").Count;
            Assert.True(expected > 0);

            foreach (var (code, _) in UserGuide.Languages)
            {
                var sections = UserGuide.GetSections(code);
                Assert.Equal(expected, sections.Count); // 언어별로 섹션 수가 같아야 번역 누락이 없다
                Assert.All(sections, s =>
                {
                    Assert.False(string.IsNullOrWhiteSpace(s.Heading));
                    Assert.False(string.IsNullOrWhiteSpace(s.Body));
                });
            }
        }

        [Fact]
        public void GetSections_CoversCurrentFeatureSet()
        {
            string all = string.Join("\n", UserGuide.GetSections("en").Select(s => s.Heading + "\n" + s.Body));
            foreach (string topic in new[] { "profile", "Risky only", "Unapprove", "Evidence", "SSDP", "passive", "FTPS", "outbox", "snooze", "PDF", "diagnostic", "Restore", "beta", "netscan-service" })
                Assert.Contains(topic, all);
        }

        [Fact]
        public void GetSections_UnknownLanguage_FallsBackToEnglish()
        {
            Assert.Equal(UserGuide.GetSections("en"), UserGuide.GetSections("fr"));
            Assert.Equal(UserGuide.GetSections("en"), UserGuide.GetSections("ja"));
        }
    }
}
