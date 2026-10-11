using System;
using System.IO;
using NetworkScanner;
using NetworkScanner.Secrets;
using NetworkScanner.Upload;

namespace NetworkScanner.Tests
{
    public class AppSettingsStoreTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "nstest-settings-" + Guid.NewGuid().ToString("N"));

        public AppSettingsStoreTests()
        {
            Directory.CreateDirectory(_root);
            UserDataPaths.OverrideRoot = _root;
            AppSettingsStore.SecretStore = new EncryptedFileSecretStore(_root);
        }

        public void Dispose()
        {
            UserDataPaths.OverrideRoot = null;
            AppSettingsStore.SecretStore = null!;
            try { Directory.Delete(_root, true); } catch { }
        }

        [Fact]
        public void SaveAndLoad_RoundTripsSettings_WithSecretsOutsideJson()
        {
            var data = new AppSettingsData
            {
                UseScheduling = true,
                SystemName = "Office-1",
                PortList = "22/443",
                UsePortChecking = true,
                MonitorIntervalMinutes = 15,
                Language = Localization.Korean,
                ScanParallelism = 32,
            };
            data.HourEnabled[2] = true;
            data.Upload.Enabled = true;
            data.Upload.Protocol = UploadProtocol.Sftp;
            data.Upload.Host = "files.example.com";
            data.Upload.User = "scan";
            data.Upload.Password = "s3cret=with=equals";
            data.Notifications.WebhookUrl = "https://hooks.example/abc";
            data.Notifications.SmtpPassword = "mailpw";

            AppSettingsStore.SaveSettings(data);

            string json = File.ReadAllText(AppSettingsStore.SettingsPath);
            Assert.DoesNotContain("s3cret", json);
            Assert.DoesNotContain("mailpw", json);
            Assert.Contains("\"sftp\"", json);

            AppSettingsData loaded = AppSettingsStore.LoadSettings();
            Assert.True(loaded.UseScheduling);
            Assert.True(loaded.HourEnabled[2]);
            Assert.Equal("Office-1", loaded.SystemName);
            Assert.Equal(UploadProtocol.Sftp, loaded.Upload.Protocol);
            Assert.Equal("s3cret=with=equals", loaded.Upload.Password);
            Assert.Equal("mailpw", loaded.Notifications.SmtpPassword);
            Assert.Equal(32, loaded.ScanParallelism);
            Assert.Equal(Localization.Korean, loaded.Language);
        }

        [Fact]
        public void LegacyIniFiles_AreMigratedOnce_IncludingBase64Password()
        {
            File.WriteAllLines(Path.Combine(_root, "setting.ini"), new[]
            {
                "usescheuling=True", "hr03=True", "useftp=True", "ftpip=10.0.0.9", "ftpid=bob",
                "ftppw=B64:" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("pw1")),
                "ftpport=2121", "systemname=Legacy", "portlist=21/22", "useportchecking=True",
                "loadlastestfile=False", "monitorintervalminutes=7", "language=ko",
            });
            File.WriteAllLines(Path.Combine(_root, "iprange.ini"), new[] { "0,192.168.1.1,192.168.1.50,office, floor 2" });

            AppSettingsData data = AppSettingsStore.LoadSettings();
            ScanRangeList ranges = AppSettingsStore.LoadScanRanges();

            Assert.True(data.UseScheduling);
            Assert.True(data.HourEnabled[2]);
            Assert.True(data.Upload.Enabled);
            Assert.Equal(UploadProtocol.Ftp, data.Upload.Protocol);
            Assert.True(data.Upload.AllowInsecure);
            Assert.Equal("10.0.0.9", data.Upload.Host);
            Assert.Equal(2121, data.Upload.Port);
            Assert.Equal("pw1", data.Upload.Password);
            Assert.Equal("Legacy", data.SystemName);
            Assert.False(data.LoadLatestFileOnStartup);
            Assert.Equal(7, data.MonitorIntervalMinutes);
            Assert.Single(ranges);
            Assert.Equal("office, floor 2", ranges[0].Description);

            Assert.True(File.Exists(AppSettingsStore.SettingsPath));
            Assert.False(File.Exists(Path.Combine(_root, "setting.ini")));
            Assert.True(File.Exists(Path.Combine(_root, "setting.ini.migrated")));
        }

        [Fact]
        public void SaveColumnLayout_DoesNotClobberOtherSettings()
        {
            var data = new AppSettingsData { SystemName = "keep-me" };
            data.Upload.Password = "pw";
            AppSettingsStore.SaveSettings(data);

            AppSettingsStore.SaveColumnLayout("1,2,3", "4,5");

            AppSettingsData loaded = AppSettingsStore.LoadSettings();
            Assert.Equal("keep-me", loaded.SystemName);
            Assert.Equal("1,2,3", loaded.IpListColumnWidths);
            Assert.Equal("pw", loaded.Upload.Password);
        }

        [Fact]
        public void CorruptJson_IsBackedUp_AndDefaultsAreReturned()
        {
            File.WriteAllText(AppSettingsStore.SettingsPath, "{ not json");
            string? err = null;
            AppSettingsStore.OnError = m => err = m;

            AppSettingsData data = AppSettingsStore.LoadSettings();

            Assert.Equal("22/80/8080", data.PortList);
            Assert.NotNull(err);
            Assert.True(File.Exists(AppSettingsStore.SettingsPath + ".corrupt"));
            AppSettingsStore.OnError = null;
        }

        [Fact]
        public void Validate_ReportsInvalidUploadAndIntervalSettings()
        {
            var data = new AppSettingsData { MonitorIntervalMinutes = 0, UsePortChecking = true, PortList = "abc" };
            data.Upload.Enabled = true;
            data.Upload.Host = "not a host!";
            data.Upload.Protocol = UploadProtocol.Ftp;

            var errors = data.Validate();

            Assert.Contains(Localization.T("settings.invalid.interval"), errors);
            Assert.Contains(Localization.T("settings.invalid.portlist"), errors);
            Assert.Contains(Localization.T("settings.invalid.ftphost"), errors);
            Assert.Contains(Localization.T("settings.invalid.insecureftp"), errors);
            Assert.Contains(Localization.T("settings.invalid.systemname"), errors);
        }

        [Fact]
        public void Validate_AcceptsHostNamesAndDefaults()
        {
            var data = new AppSettingsData { SystemName = "x" };
            data.Upload.Enabled = true;
            data.Upload.Host = "files.example.com";
            Assert.Empty(data.Validate());
        }
    }
}
