using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using NetworkScanner;

namespace NetworkScanner.Tests
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

    public class AnnotationStoreTests
    {
        [Fact]
        public void SaveThenLoad_RoundTripsNameAndDescription()
        {
            // 사용자 프로필의 실제 데이터를 건드리지 않도록 저장 위치를 테스트 폴더로 돌린다.
            UserDataPaths.OverrideRoot = Directory.GetCurrentDirectory();
            string path = UserDataPaths.Resolve(AnnotationStore.FileName);
            File.Delete(path);
            try
            {
                var items = new IPInfoList
                {
                    new IPInfo { Ip = "10.0.0.1", SystemName = "회의실 PC", Description = "3층, 담당: 홍길동" },
                    new IPInfo { Ip = "10.0.0.2", SystemName = "", Description = "" }, // 빈 값은 저장하지 않음
                };
                AnnotationStore.Save(items);

                var loaded = AnnotationStore.Load();
                Assert.True(loaded.ContainsKey("10.0.0.1"));
                Assert.Equal("회의실 PC", loaded["10.0.0.1"].Name);
                Assert.Equal("3층, 담당: 홍길동", loaded["10.0.0.1"].Description);
                Assert.False(loaded.ContainsKey("10.0.0.2"));
            }
            finally
            {
                File.Delete(path);
            }
        }
    }

    public class BannerGrabTests
    {
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
                string banner = await PingTester.GrabBannerAsync("127.0.0.1", port, 1000);
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
