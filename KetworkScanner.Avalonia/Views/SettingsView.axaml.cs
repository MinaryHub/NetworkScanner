using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Platform.Storage;
using KetworkScanner.Alerts;
using KetworkScanner.Avalonia.Helpers;
using KetworkScanner.History;
using KetworkScanner.Support;
using KetworkScanner.Upload;

namespace KetworkScanner.Avalonia.Views
{
    /// <summary>
    /// 실제 설정 파일 읽기/쓰기는 KetworkScanner.Core의 AppSettingsStore에 있다.
    /// 이 클래스는 Avalonia 컨트롤과 AppSettingsData를 서로 매핑하는 얇은 어댑터 역할만 한다.
    /// </summary>
    public partial class SettingsView : UserControl
    {
        public ScanRangeList ScanRanges { get; } = new ScanRangeList();
        // 데이터 인덱스(HourEnabled[i]) 기준 배열. 화면에는 00~23시 순서로 놓이지만 저장 레이아웃은 그대로다.
        private readonly CheckBox[] _hourCheckboxes = new CheckBox[24];

        // 화면에 노출되지 않는 값(컬럼 너비, 고지 확인, 스캔 프로필 등)을 저장 시 잃지 않도록 마지막으로 읽은 설정을 보관한다.
        private AppSettingsData _loaded = new AppSettingsData();

        // 심층 발견 서비스는 앱 시작 시 한 번 만들어지므로, 그때의 값과 달라지면 재시작 안내를 띄운다.
        private readonly string _startupDiscovery;

        public void MarkUsageNoticeAccepted() => _loaded.UsageNoticeAccepted = true;

        // 설정이 저장될 때마다 발생. MainWindow가 엔진 옵션(동시성/상한)을 갱신하는 데 쓴다.
        public event Action<AppSettingsData>? SettingsSaved;

        // "지금 백업"/진단 번들이 쓰는 이력 DB. MainWindow가 엔진과 같은 인스턴스를 넘겨준다(null이면 백업 불가).
        private ScanHistoryStore? _history;

        public SettingsView()
        {
            InitializeComponent();
            BuildHourCheckboxes();
            LoadFromStore();
            _startupDiscovery = DiscoveryFingerprint(_loaded);
        }

        public void SetHistory(ScanHistoryStore? history)
        {
            _history = history;
            BtnBackupNow.IsEnabled = history != null;
        }

        // IP 목록 화면의 프로필 콤보에서 바꾼 값을 기억해 둔다(저장은 그쪽에서 이미 했고, 이 화면의 저장이 되돌리지 않도록).
        public void SetScanProfile(string name) => _loaded.ScanProfile = ScanProfiles.Name(ScanProfiles.Parse(name));

        // 화면은 00~23시 순서. 데이터 인덱스는 AppSettingsData.IsInScheduleHour와 같은 규칙(0시 → [23], h시 → [h-1])을 따른다.
        private static int HourIndex(int clockHour) => clockHour == 0 ? 23 : clockHour - 1;

        private void BuildHourCheckboxes()
        {
            for (int hour = 0; hour < 24; hour++)
            {
                var checkBox = new CheckBox { Content = Localization.IsKorean ? $"{hour:D2}시" : $"{hour:D2}h", Margin = new global::Avalonia.Thickness(8, 2) };
                _hourCheckboxes[HourIndex(hour)] = checkBox;
                HourCheckboxPanel.Children.Add(checkBox);
            }
        }

        // 재시작이 필요한 발견 설정만 모은 비교용 문자열(이력 병합·타임아웃·이름 프로브는 저장 즉시 반영되므로 제외).
        private static string DiscoveryFingerprint(AppSettingsData d)
        {
            DiscoverySettings s = d.Discovery;
            return string.Join("|", s.Ssdp, s.MdnsBrowse, s.Smb, s.Ssh, s.Http, s.UdpProbes, s.NeighborTables,
                s.GatewaySnmp, s.SnmpAgents.Trim(), s.ActiveArp, s.PassiveListener, d.Identity.SnmpCommunity.Trim());
        }

        private void UpdateDiscoveryRestartHint() => TbDiscoveryRestart.IsVisible = DiscoveryFingerprint(_loaded) != _startupDiscovery;

        private void LoadFromStore()
        {
            ScanRanges.Clear();
            foreach (var range in AppSettingsStore.LoadScanRanges())
            {
                ScanRanges.AddItem(range);
            }
            RefreshGrid();

            ApplySettingsToControls(AppSettingsStore.LoadSettings());
        }

        private void ApplySettingsToControls(AppSettingsData data)
        {
            _loaded = data;
            ChkScheduling.IsChecked = data.UseScheduling;
            for (int i = 0; i < 24; i++) _hourCheckboxes[i].IsChecked = data.HourEnabled[i];

            UploadSettings up = data.Upload;
            ChkUseUpload.IsChecked = up.Enabled;
            SelectByTag(CmbUploadProtocol, up.Protocol.ToString(), fallbackIndex: 1); // 못 찾으면 FTPS(explicit)
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
            TbRiskAllow.Text = data.RiskAllowList;
            ChkLoadLatestFileWhenStartup.IsChecked = data.LoadLatestFileOnStartup;
            ChkContinuousMonitoring.IsChecked = data.ContinuousMonitoring;
            TbMonitorInterval.Text = data.MonitorIntervalMinutes.ToString();
            CmbLanguage.SelectedIndex = data.Language == Localization.Korean ? 1 : 0;

            ChkAlertUnapproved.IsChecked = data.AssetPolicy.AlertOnUnapproved;
            ChkAutoApprove.IsChecked = data.AssetPolicy.AutoApproveFirstScan;
            TbHighRisk.Text = data.AssetPolicy.HighRiskThreshold.ToString();

            TbRenotify.Text = data.Alerts.RenotifyAfterHours.ToString();
            TbMaintenance.Text = data.Alerts.MaintenanceWindows;

            ChkSnmp.IsChecked = data.Identity.Snmp;
            TbSnmpCommunity.Text = data.Identity.SnmpCommunity;
            ChkMdns.IsChecked = data.Identity.Mdns;
            ChkNetBios.IsChecked = data.Identity.NetBios;
            ChkVuln.IsChecked = data.AssessVulnerabilities;
            ChkDiscSsdp.IsChecked = data.Discovery.Ssdp;
            ChkDiscMdns.IsChecked = data.Discovery.MdnsBrowse;
            ChkDiscSmb.IsChecked = data.Discovery.Smb;
            ChkDiscSsh.IsChecked = data.Discovery.Ssh;
            ChkDiscHttp.IsChecked = data.Discovery.Http;
            ChkDiscUdp.IsChecked = data.Discovery.UdpProbes;
            ChkDiscNeighbor.IsChecked = data.Discovery.NeighborTables;
            ChkDiscMergeHistory.IsChecked = data.Discovery.MergeHistory;
            ChkDiscGatewaySnmp.IsChecked = data.Discovery.GatewaySnmp;
            TbDiscSnmpAgents.Text = data.Discovery.SnmpAgents;
            ChkDiscActiveArp.IsChecked = data.Discovery.ActiveArp;
            ChkDiscPassive.IsChecked = data.Discovery.PassiveListener;

            TbRetention.Text = data.HistoryRetentionDays.ToString();
            TbBackups.Text = data.HistoryBackupsToKeep.ToString();
            ChkUpdateAutoCheck.IsChecked = data.Update.AutoCheck;
            ChkUpdateAutoDownload.IsChecked = data.Update.AutoDownload;
            ChkUpdateAutoApply.IsChecked = data.Update.AutoApply;
            ChkUpdatePrerelease.IsChecked = data.Update.IncludePrerelease;
            TbUpdateInterval.Text = data.Update.CheckIntervalHours.ToString();
            ChkRefDataAuto.IsChecked = data.ReferenceData.AutoUpdate;
            TbRefDataInterval.Text = data.ReferenceData.CheckIntervalHours.ToString();
            UpdateUpdateToggles();
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
                // 숫자가 아니면 -1로 두어 Validate()(또는 ValidateNumbers())가 걸러내게 한다. 조용히 기본값으로 바꾸지 않는다.
                ScanParallelism = ParseInt(TbScanParallelism.Text),
                MaxTargets = ParseInt(TbMaxTargets.Text),
                SystemName = TbCurSystemName.Text ?? "",
                PortList = TbPortsList.Text ?? "",
                UsePortChecking = ChkCheckPort.IsChecked == true,
                RiskAllowList = TbRiskAllow.Text ?? "",
                UsageNoticeAccepted = _loaded.UsageNoticeAccepted,
                LoadLatestFileOnStartup = ChkLoadLatestFileWhenStartup.IsChecked == true,
                ContinuousMonitoring = ChkContinuousMonitoring.IsChecked == true,
                MonitorIntervalMinutes = ParseInt(TbMonitorInterval.Text),
                Language = CmbLanguage.SelectedIndex == 1 ? Localization.Korean : Localization.English,
                IpListColumnWidths = _loaded.IpListColumnWidths,
                IpRangeColumnWidths = _loaded.IpRangeColumnWidths,
                AssetPolicy = new AssetPolicySettings
                {
                    AlertOnUnapproved = ChkAlertUnapproved.IsChecked == true,
                    AutoApproveFirstScan = ChkAutoApprove.IsChecked == true,
                    HighRiskThreshold = ParseInt(TbHighRisk.Text),
                },
                Alerts = new AlertSettings
                {
                    RenotifyAfterHours = ParseInt(TbRenotify.Text),
                    MaintenanceWindows = (TbMaintenance.Text ?? "").Trim(),
                },
                Identity = new IdentitySettings
                {
                    Snmp = ChkSnmp.IsChecked == true,
                    SnmpCommunity = string.IsNullOrWhiteSpace(TbSnmpCommunity.Text) ? "public" : TbSnmpCommunity.Text!.Trim(),
                    Mdns = ChkMdns.IsChecked == true,
                    NetBios = ChkNetBios.IsChecked == true,
                },
                AssessVulnerabilities = ChkVuln.IsChecked == true,
                Discovery = new DiscoverySettings
                {
                    Ssdp = ChkDiscSsdp.IsChecked == true,
                    MdnsBrowse = ChkDiscMdns.IsChecked == true,
                    Smb = ChkDiscSmb.IsChecked == true,
                    Ssh = ChkDiscSsh.IsChecked == true,
                    Http = ChkDiscHttp.IsChecked == true,
                    UdpProbes = ChkDiscUdp.IsChecked == true,
                    NeighborTables = ChkDiscNeighbor.IsChecked == true,
                    MergeHistory = ChkDiscMergeHistory.IsChecked == true,
                    GatewaySnmp = ChkDiscGatewaySnmp.IsChecked == true,
                    SnmpAgents = TbDiscSnmpAgents.Text ?? "",
                    ActiveArp = ChkDiscActiveArp.IsChecked == true,
                    PassiveListener = ChkDiscPassive.IsChecked == true,
                    DiscoveryTimeoutMs = _loaded.Discovery.DiscoveryTimeoutMs,
                    ProbeTimeoutMs = _loaded.Discovery.ProbeTimeoutMs,
                },
                ScanProfile = ScanProfiles.Name(ScanProfiles.Parse(_loaded.ScanProfile)),
                HistoryRetentionDays = ParseInt(TbRetention.Text),
                Update = new UpdateSettings
                {
                    AutoCheck = ChkUpdateAutoCheck.IsChecked == true,
                    AutoDownload = ChkUpdateAutoDownload.IsChecked == true,
                    AutoApply = ChkUpdateAutoApply.IsChecked == true,
                    IncludePrerelease = ChkUpdatePrerelease.IsChecked == true,
                    CheckIntervalHours = ParseInt(TbUpdateInterval.Text),
                },
                ReferenceData = new ReferenceDataSettings
                {
                    AutoUpdate = ChkRefDataAuto.IsChecked == true,
                    CheckIntervalHours = ParseInt(TbRefDataInterval.Text),
                    SourceUrl = _loaded.ReferenceData.SourceUrl,
                },
                HistoryBackupsToKeep = ParseInt(TbBackups.Text),
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

        // 숫자가 아니거나 비어 있으면 -1(검증에서 걸러짐).
        private static int ParseInt(string? text)
            => int.TryParse((text ?? "").Trim(), out int v) ? v : -1;

        // Core의 Validate()가 다루지 않는 숫자 칸(최대 주소 수, 고위험 기준, 백업 개수)은 여기서 걸러낸다.
        private List<string> ValidateNumbers(AppSettingsData data)
        {
            var errors = new List<string>();
            if (!int.TryParse((TbMaxTargets.Text ?? "").Trim(), out _))
                errors.Add(string.Format(Localization.T("settings.invalid.number"), Localization.T("settings.maxtargets")));
            else if (data.MaxTargets < 1)
                errors.Add(Localization.T("settings.invalid.maxtargets"));

            if (!int.TryParse((TbHighRisk.Text ?? "").Trim(), out _))
                errors.Add(string.Format(Localization.T("settings.invalid.number"), Localization.T("settings.highrisk")));
            else if (data.AssetPolicy.HighRiskThreshold < 0 || data.AssetPolicy.HighRiskThreshold > 100)
                errors.Add(Localization.T("settings.invalid.highrisk"));

            if (!int.TryParse((TbBackups.Text ?? "").Trim(), out _))
                errors.Add(string.Format(Localization.T("settings.invalid.number"), Localization.T("settings.backups")));
            else if (data.HistoryBackupsToKeep < 0)
                errors.Add(Localization.T("settings.invalid.backups"));
            return errors;
        }

        private static string? SelectedTag(ComboBox combo) => (combo.SelectedItem as ComboBoxItem)?.Tag as string;

        // Tag가 일치하는 항목을 고른다. 없으면 fallbackIndex(호출자가 명시)로 간다.
        private static void SelectByTag(ComboBox combo, string tag, int fallbackIndex)
        {
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i] is ComboBoxItem item && string.Equals(item.Tag as string, tag, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }
            combo.SelectedIndex = fallbackIndex;
        }

        // 토큰은 HTTPS에서만, 평문 허용은 FTP에서만, 서버 지문(FTPS 인증서/SFTP 호스트 키)은 HTTPS가 아닐 때만 의미가 있다.
        private void CmbUploadProtocol_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (TbUploadToken == null || ChkUploadAllowInsecure == null || TbUploadFingerprint == null) return;
            UploadProtocol protocol = UploadSettings.ParseProtocol(SelectedTag(CmbUploadProtocol));
            TbUploadToken.IsEnabled = protocol == UploadProtocol.Https;
            ChkUploadAllowInsecure.IsEnabled = protocol == UploadProtocol.Ftp;
            TbUploadFingerprint.IsEnabled = protocol != UploadProtocol.Https;
        }

        // 자동 확인이 꺼져 있으면 백그라운드 다운로드/종료 시 설치는 일어날 수 없으므로 비활성 표시한다.
        private void ChkUpdateAutoCheck_Changed(object? sender, RoutedEventArgs e) => UpdateUpdateToggles();

        private void UpdateUpdateToggles()
        {
            if (ChkUpdateAutoDownload == null || ChkUpdateAutoApply == null) return;
            bool autoCheck = ChkUpdateAutoCheck.IsChecked == true;
            ChkUpdateAutoDownload.IsEnabled = autoCheck;
            ChkUpdateAutoApply.IsEnabled = autoCheck;
        }

        public string GetColumnWidths() => ColumnLayout.Serialize(DgIPRange);
        public void ApplyColumnWidths(string saved) => ColumnLayout.Apply(DgIPRange, saved);

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
            List<string> errors = ValidateNumbers(data);
            errors.AddRange(data.Validate());
            if (errors.Count > 0)
            {
                TbMsg.Text = Localization.T("settings.invalid.title");
                if (TopLevel.GetTopLevel(this) is Window owner)
                    await SimpleDialogs.ShowMessageAsync(owner, string.Join("\n", errors), Localization.T("settings.invalid.title"));
                return false;
            }

            AppSettingsStore.SaveSettings(data);
            _loaded = data;
            UpdateDiscoveryRestartHint();
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

        // ---- 이력 백업/복원 ----

        // 열려 있는 DB를 VACUUM INTO로 일관되게 복사한다(backups/history-날짜.db).
        private async void BtnBackupNow_Click(object? sender, RoutedEventArgs e)
        {
            if (_history == null) return;
            try
            {
                Directory.CreateDirectory(HistoryMaintenance.BackupDirectory);
                string path = Path.Combine(HistoryMaintenance.BackupDirectory, $"history-{DateTime.Now:yyyyMMdd-HHmmss}.db");
                ScanHistoryStore history = _history;
                await Task.Run(() => history.BackupTo(path));
                TbMsg.Text = string.Format(Localization.T("msg.history.backup.saved"), path);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", "history backup failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.history.backup.failed"), ex.Message);
            }
        }

        // 백업 파일을 고르면 마커 파일에 적어 두고, 다음 시작 때 MainWindow가 엔진을 만들기 전에 덮어쓴다.
        private async void BtnRestore_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null || topLevel is not Window owner) return;

            Directory.CreateDirectory(HistoryMaintenance.BackupDirectory);
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = Localization.T("history.restore"),
                AllowMultiple = false,
                SuggestedStartLocation = await topLevel.StorageProvider.TryGetFolderFromPathAsync(HistoryMaintenance.BackupDirectory),
                FileTypeFilter = new[] { new FilePickerFileType("SQLite") { Patterns = new[] { "*.db" } } },
            });
            string? path = files.FirstOrDefault()?.TryGetLocalPath();
            if (string.IsNullOrEmpty(path)) return;

            if (!await SimpleDialogs.ShowConfirmAsync(owner, $"{Localization.T("history.restore.confirm")}\n\n{path}", Localization.T("history.restore")))
                return;

            try
            {
                HistoryRestore.Schedule(path);
                TbMsg.Text = Localization.T("msg.history.restore.pending");
                await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.history.restore.pending"), Localization.T("history.restore"));
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", "history restore schedule failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.history.restore.failed"), ex.Message);
            }
        }

        // ---- 설정 내보내기 / 가져오기 / 진단 번들 ----

        private async void BtnExport_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null) return;

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = Localization.T("settings.export"),
                SuggestedFileName = $"netscan-settings-{DateTime.Now:yyyyMMdd}.json",
                DefaultExtension = "json",
                FileTypeChoices = new[] { new FilePickerFileType("JSON") { Patterns = new[] { "*.json" } } },
            });
            string? path = file?.TryGetLocalPath();
            if (string.IsNullOrEmpty(path)) return;

            try
            {
                AppSettingsStore.Export(path);
                TbMsg.Text = string.Format(Localization.T("msg.settings.exported"), path);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", "settings export failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.settings.exportfailed"), ex.Message);
            }
        }

        // 가져온 뒤 화면과 대역 목록을 다시 읽고, 엔진 옵션도 갱신되도록 SettingsSaved를 올린다.
        private async void BtnImport_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null) return;

            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = Localization.T("settings.import"),
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("JSON") { Patterns = new[] { "*.json" } } },
            });
            string? path = files.FirstOrDefault()?.TryGetLocalPath();
            if (string.IsNullOrEmpty(path)) return;

            try
            {
                AppSettingsStore.Import(path);
                LoadFromStore();
                UpdateDiscoveryRestartHint();
                TbMsg.Text = Localization.T("msg.settings.imported");
                SettingsSaved?.Invoke(_loaded);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", "settings import failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.settings.importfailed"), ex.Message);
            }
        }

        // MainWindow가 구독해 실제 확인을 수행한다(업데이트 관리자는 창이 소유).
        public event Action? UpdateCheckRequested;
        public void ShowUpdateStatus(string text) => TbUpdateStatus.Text = text;
        private void BtnUpdateCheck_Click(object? sender, RoutedEventArgs e) => UpdateCheckRequested?.Invoke();

        private async void BtnDiag_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null) return;

            string defaultPath = DiagnosticBundle.DefaultPath();
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = Localization.T("settings.diag"),
                SuggestedFileName = Path.GetFileName(defaultPath),
                SuggestedStartLocation = await topLevel.StorageProvider.TryGetFolderFromPathAsync(Path.GetDirectoryName(defaultPath) ?? UserDataPaths.Root),
                DefaultExtension = "zip",
                FileTypeChoices = new[] { new FilePickerFileType("ZIP") { Patterns = new[] { "*.zip" } } },
            });
            string? path = file?.TryGetLocalPath();
            if (string.IsNullOrEmpty(path)) return;

            try
            {
                ScanHistoryStore? history = _history;
                string created = await Task.Run(() => DiagnosticBundle.Create(path, history: history));
                TbMsg.Text = string.Format(Localization.T("msg.diag.created"), created);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("KetworkScanner", "diagnostic bundle failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.diag.failed"), ex.Message);
            }
        }
    }
}
