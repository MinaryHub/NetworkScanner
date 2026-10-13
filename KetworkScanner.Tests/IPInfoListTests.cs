using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class IPInfoListTests
    {
        [Fact]
        public void AddItem_NewIp_IsAdded()
        {
            var list = new IPInfoList();

            list.AddItem(new IPInfo { Ip = "10.0.0.1" });

            Assert.Single(list);
        }

        [Fact]
        public void AddItem_DuplicateIp_IsIgnored()
        {
            var list = new IPInfoList();
            list.AddItem(new IPInfo { Ip = "10.0.0.1", SystemName = "first" });

            list.AddItem(new IPInfo { Ip = "10.0.0.1", SystemName = "second" });

            Assert.Single(list);
            Assert.Equal("first", list.GetItem("10.0.0.1")!.SystemName);
        }

        [Fact]
        public void DelItem_ExistingIp_IsRemoved()
        {
            var list = new IPInfoList();
            list.AddItem(new IPInfo { Ip = "10.0.0.1" });

            list.DelItem("10.0.0.1");

            Assert.False(list.IsExist("10.0.0.1"));
        }

        [Fact]
        public void GetItem_UnknownIp_ReturnsNull()
        {
            var list = new IPInfoList();

            Assert.Null(list.GetItem("10.0.0.99"));
        }
    }
}
