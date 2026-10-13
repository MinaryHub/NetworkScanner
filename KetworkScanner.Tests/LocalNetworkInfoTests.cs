using System.Net;
using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class LocalNetworkInfoTests
    {
        [Fact]
        public void GetLocalSubnetRange_WhenDetected_ReturnsValidInclusiveIPv4Range()
        {
            // CI/개발 환경마다 네트워크 인터페이스 구성이 달라 항상 감지되리라 보장할 수 없으므로,
            // 결과가 있다면 그 값이 유효한지만 검증한다(감지 실패 자체는 실패로 보지 않는다).
            ScanRangeInfo? range = LocalNetworkInfo.GetLocalSubnetRange();
            if (range == null) return;

            var start = IPAddress.Parse(range.StartIP);
            var end = IPAddress.Parse(range.EndIP);

            Assert.True(IPRangeUtil.ToUInt32(end) >= IPRangeUtil.ToUInt32(start));
            Assert.NotEqual(IPAddress.Any, start);
        }
    }
}
