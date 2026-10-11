using System;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using NetworkScanner.Avalonia.Helpers;
using NetworkScanner.Upload;

namespace NetworkScanner.Avalonia.Views
{
    /// <summary>
    /// 실제 설정 파일 읽기/쓰기는 NetworkScanner.Core의 AppSettingsStore에 있다.
    /// 이 클래스는 Avalonia 컨트롤과 AppSettingsData를 서로 매핑하는 얇은 어댑터 역할만 한다.
    /// </summary>
    public partial class SettingsView : UserControl
    {
        public ScanRangeList ScanRanges { get; } = new ScanRangeList();
        private readonly CheckBox[] _hourCheckboxes = new CheckBox[24];

        // 화면에 노출되지 않는 값(컬럼 너비 등)을 저장 시 잃지 않도록 마지막으로 읽은 설정을 보관한다.
        private AppSettingsData _loaded = new AppSettingsData();

        // 설정이 저장될 때마다 발생. MainWindow가 엔진 옵션(동시성/상한)을 갱신하는 데 쓴다.
        public event Action<AppSettingsData>? SettingsSaved;

        public SettingsView()
        {
            InitializeComponent();
            BuildHourCheckboxes();
            LoadFromStore();
        }

        private void BuildHourCheckboxes()
        {
            for (int label = 1; label <= 24; label++)
            {
                var checkBox = new CheckBox { Content = Localization.IsKorean ? $"{label:D2}시" : $"{label:D2}h", Margin = new global::Avalonia.Thickness(8, 2) };
                _hourCheckboxes[label - 1] = checkBox;
                HourCheckboxPanel.Children.Add(checkBox);
            }
        }

        private void LoadFromStore()
        {
            foreach (var range in AppSettingsStore.LoadScanRanges())
            {
                ScanRanges.AddItem(range);
            }
            DgIPRange.ItemsSource = ScanRanges;

            ApplySettingsToControls(AppSettingsStore.LoadSettings());
        }

        private void ApplySettingsToControls(AppSettingsData data)
        {
            _loaded = data;
            ChkScheduling.IsChecked = data.UseScheduling;
            for (int i = 0; i < 24; i++) _hourCheckboxes[i].IsChecked = data.HourEnabled[i];

            UploadSettings up = data.Upload;
            ChkUseUpload.IsChecked = up.Enabled;
            SelectByTag(CmbUploadProtocol, up.Protocol.ToString());
            TbUploadHost.Text = up.Host;
            TbUploadPort.Text = up.Port > 0 ? up.Port.ToString() : "";
            TbUploadUser.Text = up.User;
            TbUploadPassword.Text = up.Password;
            TbUploadRemoteDir.Text = up.RemoteDirectory;
            TbUploadFingerprint.Text = up.ServerFingerprint;
            TbUploadToken.Text = up.BearerToken;
            ChkUploadAllowInsecure.IsChecked = up.AllowInsecure;

            NotificationSettings n = data.Notifications;
            ChkUseNotify.IsChecked = n.Enabled;
            ChkNotifySecurityOnly.IsChecked = n.OnSecurityOnly;
            TbWebhookUrl.Text = n.WebhookUrl;
            TbSyslogHost.Text = n.SyslogHost;
            TbSyslogPort.Text = n.SyslogPort.ToString();
            TbSmtpHost.Text = n.SmtpHost;
            TbSmtpPort.Text = n.SmtpPort.ToString();
            ChkSmtpStartTls.IsChecked = n.SmtpUseStartTls;
            TbSmtpUser.Text = n.SmtpUser;
            TbSmtpPassword.Text = n.SmtpPassword;
            TbMailFrom.Text = n.MailFrom;
            TbMailTo.Text = n.MailTo;

            TbScanParallelism.Text = data.ScanParallelism.ToString();
            TbMaxTargets.Text = data.MaxTargets.ToString();

            TbCurSystemName.Text = data.SystemName;
            TbPortsList.Text = data.PortList;
            ChkCheckPort.IsChecked = data.UsePortChecking;
            ChkLoadLatestFileWhenStartup.IsChecked = data.LoadLatestFileOnStartup;
            ChkContinuousMonitoring.IsChecked = data.ContinuousMonitoring;
            TbMonitorInterval.Text = data.MonitorIntervalMinutes.ToString();
            CmbLanguage.SelectedIndex = data.Language == Localization.Korean ? 1 : 0;
        }

        private AppSettingsData CollectSettingsFromControls()
        {
            var data = new AppSettingsData
            {
                UseScheduling = ChkScheduling.IsChecked == true,
                Upload = new UploadSettings
                {
                    Enabled = ChkUseUpload.IsChecked == true,
                    Protocol = UploadSettings.ParseProtocol(SelectedTag(CmbUploadProtocol)),
                    Host = (TbUploadHost.Text ?? "").Trim(),
                    // 비우면 0(프로토콜 기본 포트). 숫자가 아니면 -1로 두어 Validate()가 걸러내게 한다.
                    Port = ParsePort(TbUploadPort.Text, 0),
                    User = TbUploadUser.Text ?? "",
                    Password = TbUploadPassword.Text ?? "",
                    RemoteDirectory = string.IsNullOrWhiteSpace(TbUploadRemoteDir.Text) ? "/FTP" : TbUploadRemoteDir.Text!.Trim(),
                    ServerFingerprint = (TbUploadFingerprint.Text ?? "").Trim(),
                    BearerToken = (TbUploadToken.Text ?? "").Trim(),
                    AllowInsecure = ChkUploadAllowInsecure.IsChecked == true,
                },
                Notifications = new NotificationSettings
                {
                    Enabled = ChkUseNotify.IsChecked == true,
                    OnSecurityOnly = ChkNotifySecurityOnly.IsChecked == true,
                    WebhookUrl = (TbWebhookUrl.Text ?? "").Trim(),
                    SyslogHost = (TbSyslogHost.Text ?? "").Trim(),
                    SyslogPort = ParsePort(TbSyslogPort.Text, 514),
                    SmtpHost = (TbSmtpHost.Text ?? "").Trim(),
                    SmtpPort = ParsePort(TbSmtpPort.Text, 587),
                    SmtpUseStartTls = ChkSmtpStartTls.IsChecked == true,
                    SmtpUser = TbSmtpUser.Text ?? "",
                    SmtpPassword = TbSmtpPassword.Text ?? "",
                    MailFrom = (TbMailFrom.Text ?? "").Trim(),
                    MailTo = (TbMailTo.Text ?? "").Trim(),
                },
                ScanParallelism = int.TryParse(TbScanParallelism.Text, out int par) ? par : -1,
                MaxTargets = int.TryParse(TbMaxTargets.Text, out int max) && max > 0 ? max : 65536,
                SystemName = TbCurSystemName.Text ?? "",
                PortList = TbPortsList.Text ?? "",
                UsePortChecking = ChkCheckPort.IsChecked == true,
                LoadLatestFileOnStartup = ChkLoadLatestFileWhenStartup.IsChecked == true,
                ContinuousMonitoring = ChkContinuousMonitoring.IsChecked == true,
                MonitorIntervalMinutes = int.TryParse(TbMonitorInterval.Text, out int m) ? m : -1,
                Language = CmbLanguage.SelectedIndex == 1 ? Localization.Korean : Localization.English,
                IpListColumnWidths = _loaded.IpListColumnWidths,
                IpRangeColumnWidths = _loaded.IpRangeColumnWidths,
            };

            for (int i = 0; i < 24; i++) data.HourEnabled[i] = _hourCheckboxes[i].IsChecked == true;

            return data;
        }

        // 빈 칸이면 기본값, 숫자가 아니면 -1(검증에서 걸러짐).
        private static int ParsePort(string? text, int whenBlank)
        {
            if (string.IsNullOrWhiteSpace(text)) return whenBlank;
            return int.TryParse(text.Trim(), out int p) ? p : -1;
        }

        private static string? SelectedTag(ComboBox combo) => (combo.SelectedItem as ComboBoxItem)?.Tag as string;

        private static void SelectByTag(ComboBox combo, string tag)
        {
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i] is ComboBoxItem item && string.Equals(item.Tag as string, tag, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }
            combo.SelectedIndex = 1; // Ftps
        }

        // 토큰은 HTTPS에서만, 평문 허용은 FTP에서만 의미가 있으므로 그 외에는 비활성 표시한다.
        private void CmbUploadProtocol_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (TbUploadToken == null || ChkUploadAllowInsecure == null) return;
            UploadProtocol protocol = UploadSettings.ParseProtocol(SelectedTag(CmbUploadProtocol));
            TbUploadToken.IsEnabled = protocol == UploadProtocol.Https;
            ChkUploadAllowInsecure.IsEnabled = protocol == UploadProtocol.Ftp;
        }

        public string GetColumnWidths() => ColumnLayout.Serialize(DgIPRange);
        public void ApplyColumnWidths(string csv) => ColumnLayout.Apply(DgIPRange, csv);

        public bool IsInScheduleHour(int hour) => CollectSettingsFromControls().IsInScheduleHour(hour);

        public string GetSystemName() => TbCurSystemName.Text ?? "";

        // MainWindow가 IScanConfigProvider를 구현하기 위해 화면에 반영된 현재 설정값을 읽어올 때 사용한다.
        public AppSettingsData GetCurrentSettings() => CollectSettingsFromControls();

        private void SaveScanRanges()
        {
            AppSettingsStore.SaveScanRanges(ScanRanges);
            TbMsg.Text = Localization.T("msg.range.saved");
        }

        // 검증을 통과한 경우에만 저장한다. 실패하면 오류 목록을 대화상자로 보여주고 저장하지 않는다.
        private async System.Threading.Tasks.Task<bool> SaveSettingsAsync()
        {
            AppSettingsData data = CollectSettingsFromControls();
            List<string> errors = data.Validate();
            if (errors.Count > 0)
            {
                TbMsg.Text = Localization.T("settings.invalid.title");
                if (TopLevel.GetTopLevel(this) is Window owner)
                    await SimpleDialogs.ShowMessageAsync(owner, string.Join("\n", errors), Localization.T("settings.invalid.title"));
                return false;
            }

            AppSettingsStore.SaveSettings(data);
            _loaded = data;
            TbMsg.Text = Localization.T("msg.settings.saved");
            SettingsSaved?.Invoke(data);
            return true;
        }

        private static bool IsValidIP(string val)
        {
            return System.Net.IPAddress.TryParse(val, out var parsed)
                && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        }

        private void RefreshGrid()
        {
            DgIPRange.ItemsSource = null;
            DgIPRange.ItemsSource = ScanRanges;
        }

        private async void BtnAddRange_Click(object? sender, RoutedEventArgs e)
        {
            var owner = (Window)TopLevel.GetTopLevel(this)!;

            string startText = TbStartIP.Text ?? "";
            string endText = TbEndIP.Text ?? "";

            // 시작 IP 칸에 "192.168.1.0/24" 처럼 CIDR을 입력하면 시작/종료 IP로 자동 변환한다.
            if (startText.Contains('/'))
            {
                if (!IPRangeUtil.TryParseCidr(startText, out string cs, out string ce))
                {
                    await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.cidr.invalid"));
                    return;
                }
                startText = cs;
                endText = ce;
            }

            if (!IsValidIP(startText))
            {
                await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.startip.invalid"));
                return;
            }
            if (!IsValidIP(endText))
            {
                await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.endip.invalid"));
                return;
            }

            bool added = ScanRanges.AddItem(new ScanRangeInfo
            {
                Index = 0,
                StartIP = startText,
                EndIP = endText,
                Description = TbDescription.Text ?? "",
            });

            if (!added)
            {
                await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.range.duplicate"));
                return;
            }

            TbStartIP.Text = "";
            TbEndIP.Text = "";
            TbDescription.Text = "";

            SaveScanRanges();
            RefreshGrid();
        }

        private async void BtnRemoveRange_Click(object? sender, RoutedEventArgs e)
        {
            if (DgIPRange.SelectedItem is not ScanRangeInfo item) return;

            var owner = (Window)TopLevel.GetTopLevel(this)!;
            bool confirmed = await SimpleDialogs.ShowConfirmAsync(owner, $"{item.StartIP} ~ {item.EndIP}", Localization.T("settings.removerange"));
            if (confirmed)
            {
                ScanRanges.DelItem(item.StartIP, item.EndIP);
                SaveScanRanges();
                RefreshGrid();
            }
        }

        private async void BtnSaveFile_Click(object? sender, RoutedEventArgs e)
        {
            if (await SaveSettingsAsync()) SaveScanRanges();
        }
    }
}
