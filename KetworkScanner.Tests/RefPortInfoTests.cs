using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class RefPortInfoTests
    {
        [Fact]
        public void ToString_FormatsAsPortNameProtocol()
        {
            var port = new RefPortInfo { PortNo = 80, Portname = "HTTP", Protocol = "TCP" };

            Assert.Equal("80:HTTP:TCP", port.ToString());
        }
    }
}
