using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using NetworkScanner.Alerts;
using NetworkScanner.Avalonia.Helpers;
using NetworkScanner.Reports;

namespace NetworkScanner.Avalonia.Views
{
    /// <summary>
    /// 실제 스캔/저장/불러오기 로직은 NetworkScanner.Core의 ScanEngine에 있다.
    /// 이 클래스는 Avalonia 컨트롤과 ScanEngine 이벤트를 연결하는 얇은 어댑터 역할만 한다.
    /// </summary>
    public partial class IPListView : UserControl
    {
        private readonly IPInfoList _items = new IPInfoList();
        private readonly OUIInfo _oui = new OUIInfo();
        private ScanEngine? _engine;

        public IScanConfigProvider? Config { get; set; }

        // 엔진 이벤트를 UI 스레드에서 다시 내보낸다. MainWindow가 알림 전송/outbox 갱신에 쓴다.
        // 알림 운영 규칙(중복 억제/확인/스누즈/점검 시간대)을 거친 결과. 외부 채널 알림은 이것의 ChangesToNotify만 보낸다.
        public event Action<AlertOutcome>? AlertsProcessed;
        public event Action? ScanStarted;
        public event Action? ScanFinished;
        // 상단 프로필 콤보로 스캔 프로필을 바꿔 저장했을 때(설정 화면이 따라오도록).
        public event Action<string>? ProfileChanged;

        public ScanServices? Services => _engine?.Services;

        // 프로필 콤보를 코드로 채우는 동안 SelectionChanged가 저장을 일으키지 않도록 막는다.
        private bool _profileSyncing;

        public IPListView()
        {
            InitializeComponent();
            _oui.LoadInfo();
            BuildProfileCombo();
            // DataGrid는 절대 라이브 컬렉션(_items)에 직접 바인딩하지 않는다. 병렬 스캔이 백그라운드
            // 스레드에서 _items를 수정하면 Avalonia가 UI 스레드가 아닌 곳에서 CollectionChanged를
            // 처리하려다 교착/예외에 빠지기 때문이다. 항상 락으로 뜬 스냅샷(복사본)만 바인딩한다.
            RefreshGrid();
        }

        public void Initialize(IScanConfigProvider config, ScanServices? services = null, ScanOptions? options = null)
        {
            Config = config;
            _engine = new ScanEngine(_items, _oui, Config, services, options);
            if (options != null) SetProfile(ScanProfiles.Name(options.Profile));
            // 이력 DB가 없으면 승인 자체가 불가능하므로 메뉴를 비활성화한다.
            SetMenuItemEnabled("MenuItemApprove", services?.History != null);
            SetMenuItemEnabled("MenuItemUnapprove", services?.History != null);
            _engine.Message += msg => Dispatcher.UIThread.Post(() => TbStatusLine.Text = msg);
            _engine.ProgressMaxChanged += max => Dispatcher.UIThread.Post(() =>
            {
                PbProgress.Maximum = max;
                PbProgress.Value = 0;
                UpdateProgressPercentText(0, max);
            });
            _engine.ProgressChanged += val => Dispatcher.UIThread.Post(() =>
            {
                PbProgress.Value = val;
                UpdateProgressPercentText(val, (int)PbProgress.Maximum);
            });
            _engine.ResultsSummaryChanged += (alive, dead, total) => Dispatcher.UIThread.Post(() =>
            {
                TbTotal.Text = total.ToString();
                TbUp.Text = alive.ToString();
                TbDown.Text = dead.ToString();
            });
            _engine.ItemsRefreshNeeded += RequestGridRefresh;
            _engine.ScanStarted += () => Dispatcher.UIThread.Post(() =>
            {
                SetScanningState(true);
                ScanStarted?.Invoke();
            });
            _engine.ScanFinished += () => Dispatcher.UIThread.Post(() =>
            {
                SetScanningState(false);
                RefreshGrid();
                TbProgressPercent.Text = "";
                ScanFinished?.Invoke();
            });
            _engine.ScanChangesDetected += changes => Dispatcher.UIThread.Post(() => ReportChanges(changes));
            _engine.AlertsProcessed += outcome => Dispatcher.UIThread.Post(() => AlertsProcessed?.Invoke(outcome));

            _engine.InitFromConfig();
        }

        // ---- 스캔 프로필 ----

        private void BuildProfileCombo()
        {
            _profileSyncing = true;
            foreach (ScanProfileKind kind in ScanProfiles.All)
                CmbProfile.Items.Add(new ComboBoxItem { Content = ScanProfiles.DisplayName(kind), Tag = ScanProfiles.Name(kind) });
            CmbProfile.SelectedIndex = ScanProfiles.All.ToList().IndexOf(ScanProfileKind.Standard);
            _profileSyncing = false;
        }

        // 설정 화면에서 저장한 프로필을 콤보에 반영한다(저장은 하지 않음).
        public void SetProfile(string name)
        {
            string tag = ScanProfiles.Name(ScanProfiles.Parse(name));
            _profileSyncing = true;
            try
            {
                for (int i = 0; i < CmbProfile.Items.Count; i++)
                {
                    if (CmbProfile.Items[i] is ComboBoxItem item && (item.Tag as string) == tag) { CmbProfile.SelectedIndex = i; break; }
                }
            }
            finally { _profileSyncing = false; }
        }

        // 사용자가 콤보에서 고르면: 설정 파일에 저장 → 엔진 옵션 갱신 → 설정 화면에 통보.
        private void CmbProfile_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (_profileSyncing || _engine == null) return;
            if ((CmbProfile.SelectedItem as ComboBoxItem)?.Tag is not string tag) return;

            try
            {
                AppSettingsData data = AppSettingsStore.LoadSettings();
                data.ScanProfile = tag;
                AppSettingsStore.SaveSettings(data);
                ApplyOptions(ScanOptions.FromSettings(data));
                ProfileChanged?.Invoke(tag);
                TbMsg.Text = string.Format(Localization.T("msg.profile.applied"), ScanProfiles.DisplayName(ScanProfiles.Parse(tag)));
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "profile change failed", ex);
                TbMsg.Text = ex.Message;
            }
        }

        // ContextMenu 안의 항목은 이름 범위로 못 찾을 수 있어 Items를 직접 훑는다.
        private void SetMenuItemEnabled(string name, bool enabled)
        {
            if (DgIPList.ContextMenu is not ContextMenu menu) return;
            foreach (object? item in menu.Items)
                if (item is MenuItem mi && mi.Name == name) mi.IsEnabled = enabled;
        }

        // 직전 스캔 대비 변화를 로그에 남기고, 보안상 중요한 변화(MAC 변경/위험 포트)는 팝업으로 경고한다.
        private async void ReportChanges(System.Collections.Generic.IReadOnlyList<ScanChange> changes)
        {
            var security = new System.Collections.Generic.List<string>();
            foreach (ScanChange c in changes)
            {
                string line = ScanDiff.Describe(c);
                if (ScanDiff.IsSecurityRelevant(c.Type)) { AppLogger.LogError("NetworkScanner", line); security.Add(line); }
                else AppLogger.LogInfo("NetworkScanner", line);
            }

            TbMsg.Text = $"{changes.Count} {Localization.T("change.detected")}"
                + (security.Count > 0 ? $" ({security.Count} {Localization.T("change.securityalert")})" : "");

            if (security.Count > 0 && TopLevel.GetTopLevel(this) is Window owner)
            {
                await SimpleDialogs.ShowMessageAsync(owner, string.Join("\n", security), Localization.T("change.dialogtitle"));
            }
        }

        // 사용자가 조절한 컬럼 너비를 컬럼 Tag 기준 문자열로 반환한다(설정 저장용).
        public string GetColumnWidths() => ColumnLayout.Serialize(DgIPList);

        // 저장된 컬럼 너비를 복원한다(앱 시작 시 호출).
        public void ApplyColumnWidths(string saved) => ColumnLayout.Apply(DgIPList, saved);

        // 병렬 스캔은 초당 수백 번 갱신을 요청할 수 있으므로, 이미 예약된 갱신이 있으면 무시해 병합한다.
        private volatile bool _refreshPending;
        private void RequestGridRefresh()
        {
            if (_refreshPending) return;
            _refreshPending = true;
            Dispatcher.UIThread.Post(() =>
            {
                _refreshPending = false;
                RefreshGrid();
            }, DispatcherPriority.Background);
        }

        // 스캔 진행 중에는 "스캔" 버튼을 비활성화하고 "취소" 버튼만 눌리도록 해 중복 스캔 시작을 막는다.
        private void SetScanningState(bool scanning)
        {
            BtnScan.IsEnabled = !scanning;
            BtnStop.IsEnabled = scanning;
            TbScanLabel.Text = scanning ? Localization.T("btn.scanning") : Localization.T("btn.scan");
        }

        // 진행률 바 위에 겹쳐 보여줄 "N% (진행/전체)" 텍스트를 계산한다. 전체 개수가 0이면(스캔 시작 전) 비워둔다.
        private void UpdateProgressPercentText(int value, int max)
        {
            TbProgressPercent.Text = max > 0 ? $"{value * 100 / max}% ({value}/{max})" : "";
        }

        private void RefreshGrid()
        {
            List<IPInfo> shown = FilterItems();
            DgIPList.ItemsSource = null;
            DgIPList.ItemsSource = shown;
            TbResult.Text = shown.Count.ToString();

            // 위험(위험 포트 또는 고위험 점수) 호스트 수는 요약 이벤트에 없으므로 스냅샷에서 센다. 0이면 타일을 조용한 흰색으로 둔다.
            int risk;
            object sync = _engine?.ItemsSyncRoot ?? _items;
            lock (sync) risk = _items.Count(i => i.StatusKey == "warn");
            TbRisk.Text = risk.ToString();
            TileRisk.Classes.Set("risk", risk > 0);
        }

        // 병렬 스캔 중 워커 스레드가 _items를 수정할 수 있으므로, 엔진의 쓰기 락을 잡고 스냅샷(복사본)을
        // 만들어 반환한다. DataGrid는 이 고정된 복사본만 열람하므로 열람 중 컬렉션 변경 예외가 나지 않는다.
        private List<IPInfo> FilterItems()
        {
            object sync = _engine?.ItemsSyncRoot ?? _items;
            string keyword = TbSearch.Text?.Trim() ?? "";
            bool aliveOnly = ChkAliveOnly.IsChecked == true;
            bool riskOnly = ChkRiskOnly.IsChecked == true;
            lock (sync)
            {
                return _items.Where(i =>
                        (!aliveOnly || i.Alive)
                        && (!riskOnly || i.StatusKey == "warn")
                        && (string.IsNullOrEmpty(keyword) || Matches(i, keyword)))
                    .ToList();
            }
        }

        private void Filter_Changed(object? sender, RoutedEventArgs e) => RefreshGrid();

        // 검색은 표에 보이는 텍스트 컬럼 전부를 대상으로 한다(파생값인 종류/OS 추정 포함).
        private static bool Matches(IPInfo info, string keyword)
        {
            return Has(info.Ip) || Has(info.SystemName) || Has(info.Macaddr) || Has(info.Vendor)
                || Has(info.Ports) || Has(info.Description) || Has(info.Model) || Has(info.OsVersion)
                || Has(info.DeviceType) || Has(info.OsGuess) || Has(info.Service) || Has(info.SwitchPort);

            bool Has(string? text) => text?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false;
        }

        private void TbSearch_TextChanged(object? sender, TextChangedEventArgs e) => RefreshGrid();

        public void ClearItems()
        {
            _items.Clear();
            RefreshGrid();
        }

        public void LoadIPInfo(string filename)
        {
            _engine?.LoadIPInfo(filename);
            RefreshGrid();
        }

        // 설정 저장 후 동시성/상한을 바꿔 적용한다(진행 중인 스캔에는 영향 없음, 다음 스캔부터).
        // 참조 데이터(OUI)가 갱신되면 제조사 테이블을 다시 읽는다. 포트 목록은 RefPortListView가, 취약점 규칙은 RuleEngine.Reload()가 맡는다.
        public void ReloadReferenceData() => _oui.LoadInfo();

        public void ApplyOptions(ScanOptions options)
        {
            if (_engine != null) _engine.Options = options;
        }

        public void SchedulingScan() => _engine?.StartSchedulingScan(Config?.GetSystemName() ?? "");

        // 연속 모니터링용: 자동저장 없이 전체 대역을 재스캔한다(변화 감지 알림은 그대로 동작).
        public void StartScan() => _engine?.StartRefreshAllRange(Config?.GetSystemName() ?? "");

        public bool IsScanning() => _engine?.IsScanning() ?? false;

        public void GetLatestFilePath(string prefixName) => _engine?.GetLatestFilePath(prefixName);

        private void BtnScan_Click(object? sender, RoutedEventArgs e)
        {
            _engine?.StartRefreshAllRange(Config?.GetSystemName() ?? "");
        }

        private void BtnStop_Click(object? sender, RoutedEventArgs e)
        {
            _engine?.ScanningStop();
        }

        private async void BtnNewFile_Click(object? sender, RoutedEventArgs e)
        {
            var owner = (Window)TopLevel.GetTopLevel(this)!;
            if (await SimpleDialogs.ShowConfirmAsync(owner, Localization.T("msg.deleteall"), Localization.T("msg.delete")))
            {
                ClearItems();
            }
        }

        private async void BtnLoadFile_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null) return;

            string envDir = ScanEngine.GetEnvDirectory();
            Directory.CreateDirectory(envDir);

            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = Localization.T("iplist.open.title"),
                AllowMultiple = false,
                SuggestedStartLocation = await topLevel.StorageProvider.TryGetFolderFromPathAsync(envDir),
                FileTypeFilter = new[] { new FilePickerFileType(Localization.T("file.csv")) { Patterns = new[] { "*.csv" } } },
            });

            var file = files.FirstOrDefault();
            if (file != null)
            {
                LoadIPInfo(file.Path.LocalPath);
            }
        }

        private async void BtnSaveFile_Click(object? sender, RoutedEventArgs e)
        {
            if (_engine == null) return;
            await _engine.WriteIPInfo(false, Config?.GetSystemName() ?? "");
        }

        private async void BtnReport_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel?.StorageProvider == null || _engine == null) return;

            List<IPInfo> snapshot;
            lock (_engine.ItemsSyncRoot) snapshot = _items.ToList();
            if (snapshot.Count == 0) { TbMsg.Text = Localization.T("msg.noresult.report"); return; }

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = Localization.T("btn.report.all"),
                SuggestedFileName = $"NetworkScanner_{System.DateTime.Now:yyyyMMdd_HHmmss}.html",
                DefaultExtension = "html",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("HTML") { Patterns = new[] { "*.html" } },
                    new FilePickerFileType("PDF") { Patterns = new[] { "*.pdf" } },
                    new FilePickerFileType("JSON") { Patterns = new[] { "*.json" } },
                },
            });
            if (file == null) return;

            string ts = System.DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string systemName = Config?.GetSystemName() ?? "";
            try
            {
                // PDF는 바이너리라 Core의 PdfReport가 직접 파일로 쓴다(임베드 폰트로 한글 포함).
                if (file.Name.EndsWith(".pdf", System.StringComparison.OrdinalIgnoreCase))
                {
                    string? path = file.TryGetLocalPath();
                    if (string.IsNullOrEmpty(path)) { TbMsg.Text = string.Format(Localization.T("msg.report.savefailed"), file.Name); return; }
                    await PdfReport.SaveAsync(path, snapshot, systemName, ts);
                    TbMsg.Text = Localization.T("msg.report.saved.pdf");
                    return;
                }

                bool json = file.Name.EndsWith(".json", System.StringComparison.OrdinalIgnoreCase);
                string content = json
                    ? ReportGenerator.BuildJson(snapshot, systemName, ts)
                    : ReportGenerator.BuildHtml(snapshot, systemName, ts);

                await using var stream = await file.OpenWriteAsync();
                await using var writer = new StreamWriter(stream);
                await writer.WriteAsync(content);
                TbMsg.Text = json ? Localization.T("msg.report.saved.json") : Localization.T("msg.report.saved.html");
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "report save failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.report.savefailed"), ex.Message);
            }
        }

        // ---- 상세 / 자산 승인 ----

        private void DgIPList_DoubleTapped(object? sender, TappedEventArgs e) => ShowDetails();

        private void MenuItemDetails_Click(object? sender, RoutedEventArgs e) => ShowDetails();

        private void ShowDetails()
        {
            if (SelectedItem == null || TopLevel.GetTopLevel(this) is not Window owner) return;
            var dialog = new HostDetailsWindow();
            dialog.Load(SelectedItem);
            _ = dialog.ShowDialog(owner);
        }

        // 선택한 호스트를 알려진 자산으로 승인/해제(이력 DB의 hosts.approved, HistoryView와 같은 SetApproved). 승인 시 현재 MAC이 승인 MAC으로 고정된다.
        private void MenuItemApprove_Click(object? sender, RoutedEventArgs e) => SetApproved(true);
        private void MenuItemUnapprove_Click(object? sender, RoutedEventArgs e) => SetApproved(false);

        private void SetApproved(bool approved)
        {
            IPInfo? info = SelectedItem;
            var history = Services?.History;
            if (info == null || history == null) return;
            try
            {
                history.SetApproved(new[] { info.Ip }, approved, DateTimeOffset.Now);
                info.Approved = approved;
                RefreshGrid();
                TbMsg.Text = string.Format(Localization.T(approved ? "msg.asset.approved" : "msg.asset.unapproved"), 1);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", approved ? "approve failed" : "unapprove failed", ex);
                TbMsg.Text = ex.Message;
            }
        }

        private async void MenuItemWakeOnLan_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null) return;
            if (string.IsNullOrWhiteSpace(SelectedItem.Macaddr))
            {
                TbMsg.Text = Localization.T("msg.wol.nomac");
                return;
            }

            bool ok = WakeOnLan.Send(SelectedItem.Macaddr);
            TbMsg.Text = ok
                ? $"{Localization.T("msg.wol.sent")} {SelectedItem.Macaddr}"
                : Localization.T("msg.wol.failed");

            if (!ok && TopLevel.GetTopLevel(this) is Window owner)
                await SimpleDialogs.ShowMessageAsync(owner, Localization.T("msg.wol.failed"));
        }

        private IPInfo? SelectedItem => DgIPList.SelectedItem as IPInfo;

        private void MenuItemPing_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null || _engine == null) return;
            _ = _engine.PingOnceAsync(SelectedItem.Ip);
        }

        private void MenuItemCheckPort_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null) return;
            _engine?.StartCheckUserPortList(SelectedItem.Ip);
        }

        private void MenuItemCheckReservedPort_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null) return;
            _engine?.StartCheckReservedPortList(SelectedItem.Ip);
        }

        private void MenuItemCheckProhibitPort_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null) return;
            _engine?.StartCheckProhibitPortList(SelectedItem.Ip);
        }

        // 스캔 워커가 동시에 _items를 쓸 수 있으므로 엔진의 쓰기 락 안에서 지운다.
        private void MenuItemRemove_Click(object? sender, RoutedEventArgs e)
        {
            if (SelectedItem == null) return;
            string ip = SelectedItem.Ip;
            object sync = _engine?.ItemsSyncRoot ?? _items;
            lock (sync) _items.DelItem(ip);
            RefreshGrid();
        }
    }
}
