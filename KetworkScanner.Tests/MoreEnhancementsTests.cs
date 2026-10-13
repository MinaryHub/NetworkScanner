using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using KetworkScanner;
using KetworkScanner.Network;

namespace KetworkScanner.Tests
{
    public class OsGuesserTests
    {
        [Theory]
        [InlineData(57, "Linux/Unix")]
        [InlineData(64, "Linux/Unix")]
        [InlineData(117, "Windows")]
        [InlineData(128, "Windows")]
        [InlineData(0, "")]
        public void FromTtl_GuessesOsFamily(int ttl, string expected)
        {
            Assert.Equal(expected, OsGuesser.FromTtl(ttl));
        }

        [Fact]
        public void FromTtl_HighTtl_IsNetworkDevice()
        {
            Assert.Equal(Localization.T("dev.network"), OsGuesser.FromTtl(250));
        }
    }

    public class WakeOnLanTests
    {
        [Fact]
        public void BuildMagicPacket_Is102Bytes_With6xFFThenMacRepeated16Times()
        {
            byte[]? packet = WakeOnLan.BuildMagicPacket("01-02-03-04-05-06");

            Assert.NotNull(packet);
            Assert.Equal(102, packet!.Length);
            for (int i = 0; i < 6; i++) Assert.Equal(0xFF, packet[i]);
            // 첫 반복의 MAC과 마지막 반복의 첫 바이트 확인
            Assert.Equal(0x01, packet[6]);
            Assert.Equal(0x06, packet[11]);
            Assert.Equal(0x01, packet[6 + 15 * 6]);
        }

        [Theory]
        [InlineData("not-a-mac")]
        [InlineData("01-02-03-04-05")]
        [InlineData("")]
        public void BuildMagicPacket_ReturnsNull_OnInvalidMac(string mac)
        {
            Assert.Null(WakeOnLan.BuildMagicPacket(mac));
        }
    }

    public class JsonReportTests
    {
        [Fact]
        public void BuildJson_ContainsHostsAndIsValidJson()
        {
            var items = new IPInfoList
            {
                new IPInfo { Ip = "10.0.0.1", Alive = true, Ports = "80/", Vendor = "Cisco Systems", Ttl = 64 },
            };

            string json = ReportGenerator.BuildJson(items, "TestSys", "2026-07-12 10:00:00");

            using var doc = System.Text.Json.JsonDocument.Parse(json); // 유효한 JSON인지 파싱으로 확인
            Assert.Contains("10.0.0.1", json);
            Assert.Contains("TestSys", json);
            Assert.Contains(Localization.T("dev.network"), json); // Cisco 제조사 -> 네트워크 장비로 추정
        }
    }

    public class BannerGrabTests
    {
        [Fact]
        public async Task GrabBannerAsync_TlsPorts_ReturnEmptyImmediately()
        {
            // 443/8443은 평문 HEAD가 통하지 않으므로(HttpProbe/TlsInspector 담당) 연결조차 하지 않고 빈 값을 돌려준다.
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Assert.Equal("", await new TcpPortProber().GrabBannerAsync("127.0.0.1", 443, 2000, CancellationToken.None));
            Assert.Equal("", await new TcpPortProber().GrabBannerAsync("127.0.0.1", 8443, 2000, CancellationToken.None));
            Assert.True(sw.ElapsedMilliseconds < 1000, $"{sw.ElapsedMilliseconds}ms");
        }

        [Fact]
        public async Task GrabBannerAsync_ReadsGreetingFromListeningServer()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var server = Task.Run(async () =>
            {
                using var client = await listener.AcceptTcpClientAsync();
                var data = System.Text.Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.0\r\n");
                await client.GetStream().WriteAsync(data);
                await Task.Delay(50);
            });
            try
            {
                string banner = await new TcpPortProber().GrabBannerAsync("127.0.0.1", port, 1000, CancellationToken.None);
                Assert.Contains("SSH-2.0-OpenSSH_9.0", banner);
            }
            finally
            {
                listener.Stop();
                await server;
            }
        }
    }
}
