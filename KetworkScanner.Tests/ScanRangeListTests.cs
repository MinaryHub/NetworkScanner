using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class ScanRangeListTests
    {
        [Fact]
        public void AddItem_NewRange_IsAdded()
        {
            var list = new ScanRangeList();

            bool added = list.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.0.0.1", EndIP = "10.0.0.10", Description = "test" });

            Assert.Single(list);
            Assert.True(added);
        }

        [Fact]
        public void AddItem_ExactDuplicateStartAndEndIP_IsIgnored()
        {
            var list = new ScanRangeList();
            list.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.0.0.1", EndIP = "10.0.0.10", Description = "first" });

            bool added = list.AddItem(new ScanRangeInfo { Index = 2, StartIP = "10.0.0.1", EndIP = "10.0.0.10", Description = "exact duplicate" });

            Assert.Single(list);
            Assert.False(added);
        }

        [Fact]
        public void AddItem_SharesStartIPButDifferentEndIP_IsAddedAsDistinctRange()
        {
            // 시작 IP만 같고 종료 IP가 다르면 서로 다른 대역이므로 둘 다 추가되어야 한다
            // (과거에는 시작/종료 IP 중 하나라도 겹치면 무조건 무시해, 정상적인 신규 대역 추가가
            // 아무 피드백 없이 조용히 실패하는 버그가 있었다).
            var list = new ScanRangeList();
            list.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.0.0.1", EndIP = "10.0.0.10", Description = "first" });

            bool added = list.AddItem(new ScanRangeInfo { Index = 2, StartIP = "10.0.0.1", EndIP = "10.0.0.99", Description = "same start, different end" });

            Assert.Equal(2, list.Count);
            Assert.True(added);
        }

        [Fact]
        public void DelItem_ExistingRange_IsRemoved()
        {
            var list = new ScanRangeList();
            list.AddItem(new ScanRangeInfo { Index = 1, StartIP = "10.0.0.1", EndIP = "10.0.0.10", Description = "test" });

            list.DelItem("10.0.0.1", "10.0.0.10");

            Assert.Empty(list);
        }
    }
}
