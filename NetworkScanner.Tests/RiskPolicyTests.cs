using NetworkScanner;

namespace NetworkScanner.Tests
{
    public class RiskPolicyTests
    {
        private static readonly int[] Prohibited = { 31337, 12345, 8080 };

        [Fact]
        public void WithoutAllowList_AnyProhibitedPortIsRisky()
        {
            var policy = new RiskPolicy(Prohibited);
            Assert.True(policy.IsRisky("10.0.0.1", 31337));
            Assert.False(policy.IsRisky("10.0.0.1", 22));
        }

        [Fact]
        public void GlobalPortException_AppliesToEveryHost()
        {
            var policy = new RiskPolicy(Prohibited, new[] { "8080" });
            Assert.False(policy.IsRisky("10.0.0.1", 8080));
            Assert.False(policy.IsRisky("192.168.9.9", 8080));
            Assert.True(policy.IsRisky("10.0.0.1", 31337));
        }

        [Fact]
        public void HostSpecificException_OnlyAppliesToThatHost()
        {
            var policy = new RiskPolicy(Prohibited, new[] { "10.0.0.5:31337", "10.0.0.6" });
            Assert.False(policy.IsRisky("10.0.0.5", 31337));
            Assert.True(policy.IsRisky("10.0.0.7", 31337));
            Assert.False(policy.IsRisky("10.0.0.6", 12345)); // 호스트 전체 허용
            Assert.True(policy.IsRisky("10.0.0.5", 12345));  // 다른 포트는 여전히 위험
        }

        [Fact]
        public void CidrException_MatchesSubnet()
        {
            var policy = new RiskPolicy(Prohibited, new[] { "10.0.1.0/24:12345" });
            Assert.False(policy.IsRisky("10.0.1.200", 12345));
            Assert.True(policy.IsRisky("10.0.2.1", 12345));
        }

        [Fact]
        public void ParseAllowList_SeparatesValidAndInvalidEntries()
        {
            var (valid, invalid) = RiskPolicy.ParseAllowList("8080, 10.0.0.5:31337; bogus 10.0.1.0/24 99999");
            Assert.Equal(new[] { "8080", "10.0.0.5:31337" }, valid);
            Assert.Equal(new[] { "bogus", "10.0.1.0/24", "99999" }, invalid);
        }
    }
}
