using System.Net;
using KetworkScanner;

namespace KetworkScanner.Tests
{
    public class IPRangeUtilTests
    {
        [Theory]
        [InlineData("0.0.0.0", 0u)]
        [InlineData("0.0.0.1", 1u)]
        [InlineData("10.0.1.250", 167772666u)]
        [InlineData("255.255.255.255", 4294967295u)]
        public void ToUInt32_ConvertsIPv4AddressToExpectedValue(string ip, uint expected)
        {
            uint actual = IPRangeUtil.ToUInt32(IPAddress.Parse(ip));

            Assert.Equal(expected, actual);
        }

        [Theory]
        [InlineData("0.0.0.0")]
        [InlineData("10.0.1.250")]
        [InlineData("255.255.255.255")]
        public void RoundTrip_ToUInt32ThenFromUInt32_ReturnsOriginalAddress(string ip)
        {
            IPAddress original = IPAddress.Parse(ip);

            IPAddress roundTripped = IPRangeUtil.FromUInt32(IPRangeUtil.ToUInt32(original));

            Assert.Equal(original, roundTripped);
        }

        [Fact]
        public void ToUInt32_RangeCrossingSubnetBoundary_ProducesContiguousSequence()
        {
            // Phase 2에서 수정한 서브넷 경계 버그(10.0.1.250 ~ 10.0.2.10)의 회귀 테스트.
            uint start = IPRangeUtil.ToUInt32(IPAddress.Parse("10.0.1.250"));
            uint end = IPRangeUtil.ToUInt32(IPAddress.Parse("10.0.2.10"));

            var addresses = new List<string>();
            for (uint v = start; v <= end; v++)
            {
                addresses.Add(IPRangeUtil.FromUInt32(v).ToString());
            }

            Assert.Equal(17, addresses.Count); // .1.250~.1.255(6개) + .2.0~.2.10(11개)
            Assert.Equal("10.0.1.250", addresses.First());
            Assert.Equal("10.0.2.10", addresses.Last());
            Assert.Contains("10.0.1.255", addresses);
            Assert.Contains("10.0.2.0", addresses);
        }
    }
}
