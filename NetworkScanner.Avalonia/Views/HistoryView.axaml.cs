using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using NetworkScanner.Avalonia.Helpers;
using NetworkScanner.History;

namespace NetworkScanner.Avalonia.Views
{
    /// <summary>
    /// SQLite 스캔 이력(ScanHistoryStore)을 보여주는 화면: 최근 스캔, 호스트 인벤토리(자산 승인/소유자·태그), 알림(확인/스누즈).
    /// 그리드에는 표시용 문자열 행만 바인딩한다(시각은 로컬 시간으로 변환).
    /// </summary>
    public partial class HistoryView : UserControl
    {
        private const int PruneDays = 90;
        private ScanHistoryStore? _history;

        // 알림 상태를 바꿨을 때(사이드바의 열린 알림 수를 MainWindow가 다시 세도록).
        public event Action? AlertsChanged;

        public HistoryView()
        {
            InitializeComponent();
        }

        // MainWindow가 엔진과 같은 ScanServices.History를 넘겨준다. null이면 이력 DB를 열지 못한 것.
        public void Initialize(ScanHistoryStore? history)
        {
            _history = history;
            bool available = history != null;
            BtnRefresh.IsEnabled = available;
            BtnPrune.IsEnabled = available;
            BtnBackup.IsEnabled = available;
            if (!available) TbMsg.Text = Localization.T("history.unavailable");
        }

        public void Refresh()
        {
            if (_history == null)
            {
                TbMsg.Text = Localization.T("history.unavailable");
                return;
            }

            // 다시 바인딩하면 선택이 사라지므로 IP/알림 id로 기억했다가 되살린다(승인 → 소유자 지정처럼 연속 작업이 편하도록).
            var selectedIps = SelectedHosts.Select(h => h.Ip).ToHashSet();
            var selectedAlertIds = SelectedAlerts.Select(a => a.Id).ToHashSet();
            try
            {
                DgScans.ItemsSource = _history.ListScans(100).Select(ScanRow.From).ToList();
                List<InventoryRow> inventory = _history.GetInventory().Select(InventoryRow.From).ToList();
                List<AlertRow> alerts = _history.ListAlerts(ChkShowResolved.IsChecked == true).Select(AlertRow.From).ToList();
                DgInventory.ItemsSource = inventory;
                DgAlerts.ItemsSource = alerts;
                foreach (InventoryRow row in inventory) if (selectedIps.Contains(row.Ip)) DgInventory.SelectedItems.Add(row);
                foreach (AlertRow row in alerts) if (selectedAlertIds.Contains(row.Id)) DgAlerts.SelectedItems.Add(row);
                TbMsg.Text = "";
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "history read failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
            UpdateSelectionButtons();
        }

        private void BtnRefresh_Click(object? sender, RoutedEventArgs e) => Refresh();

        private void ChkShowResolved_Changed(object? sender, RoutedEventArgs e)
        {
            if (_history != null && DgAlerts != null) Refresh();
        }

        private async void BtnPrune_Click(object? sender, RoutedEventArgs e)
        {
            if (_history == null) return;
            if (TopLevel.GetTopLevel(this) is not Window owner) return;

            bool confirmed = await SimpleDialogs.ShowConfirmAsync(owner, Localization.T("history.prune.confirm"), Localization.T("history.prune"));
            if (!confirmed) return;

            try
            {
                int removed = _history.Prune(DateTimeOffset.Now.AddDays(-PruneDays));
                Refresh();
                TbMsg.Text = string.Format(Localization.T("history.pruned"), removed);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "history prune failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
        }

        // 열려 있는 DB를 VACUUM INTO로 일관되게 복사한다(backups/history-날짜.db).
        private async void BtnBackup_Click(object? sender, RoutedEventArgs e)
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
                AppLogger.LogError("NetworkScanner", "history backup failed", ex);
                TbMsg.Text = string.Format(Localization.T("msg.history.backup.failed"), ex.Message);
            }
        }

        // ---- 자산 승인 / 소유자·태그 ----

        private List<InventoryRow> SelectedHosts => DgInventory.SelectedItems?.OfType<InventoryRow>().ToList() ?? new List<InventoryRow>();
        private List<AlertRow> SelectedAlerts => DgAlerts.SelectedItems?.OfType<AlertRow>().ToList() ?? new List<AlertRow>();

        private void DgInventory_SelectionChanged(object? sender, SelectionChangedEventArgs e) => UpdateSelectionButtons();
        private void DgAlerts_SelectionChanged(object? sender, SelectionChangedEventArgs e) => UpdateSelectionButtons();

        private void UpdateSelectionButtons()
        {
            bool hosts = _history != null && SelectedHosts.Count > 0;
            BtnApprove.IsEnabled = hosts;
            BtnUnapprove.IsEnabled = hosts;
            BtnSetOwner.IsEnabled = _history != null && SelectedHosts.Count == 1;

            bool alerts = _history != null && SelectedAlerts.Count > 0;
            BtnAck.IsEnabled = alerts;
            BtnSnooze.IsEnabled = alerts;
            BtnReopen.IsEnabled = alerts;
        }

        private void BtnApprove_Click(object? sender, RoutedEventArgs e) => SetApproved(true);
        private void BtnUnapprove_Click(object? sender, RoutedEventArgs e) => SetApproved(false);

        private void SetApproved(bool approved)
        {
            if (_history == null) return;
            List<string> ips = SelectedHosts.Select(h => h.Ip).ToList();
            if (ips.Count == 0) return;
            try
            {
                int n = _history.SetApproved(ips, approved, DateTimeOffset.Now);
                Refresh();
                TbMsg.Text = string.Format(Localization.T(approved ? "msg.asset.approved" : "msg.asset.unapproved"), n);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "set approved failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
        }

        // 소유자/태그/메모를 작은 입력 대화상자로 받는다(현재 값을 미리 채움).
        private async void BtnSetOwner_Click(object? sender, RoutedEventArgs e)
        {
            if (_history == null || TopLevel.GetTopLevel(this) is not Window owner) return;
            InventoryRow? host = SelectedHosts.FirstOrDefault();
            if (host == null) return;

            string[]? values = await SimpleDialogs.ShowInputAsync(owner, $"{Localization.T("assets.setowner")} - {host.Ip}",
                new InputField(Localization.T("assets.owner"), host.Owner),
                new InputField(Localization.T("assets.tags"), host.Tags, "lab, printer, critical"),
                new InputField(Localization.T("assets.note"), host.Note));
            if (values == null) return;

            try
            {
                _history.SetHostMeta(host.Ip, values[0].Trim(), values[1].Trim(), values[2].Trim());
                Refresh();
                TbMsg.Text = string.Format(Localization.T("msg.asset.metasaved"), host.Ip);
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "set host meta failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
        }

        // ---- 알림 상태 ----

        private void BtnAck_Click(object? sender, RoutedEventArgs e) => SetAlertState(AlertState.Acknowledged, null);
        private void BtnSnooze_Click(object? sender, RoutedEventArgs e) => SetAlertState(AlertState.Snoozed, DateTimeOffset.Now.AddHours(24));
        private void BtnReopen_Click(object? sender, RoutedEventArgs e) => SetAlertState(AlertState.Open, null);

        private void SetAlertState(AlertState state, DateTimeOffset? snoozeUntil)
        {
            if (_history == null) return;
            List<AlertRow> selected = SelectedAlerts;
            if (selected.Count == 0) return;
            try
            {
                foreach (AlertRow a in selected) _history.SetAlertState(a.Id, state, snoozeUntil);
                Refresh();
                TbMsg.Text = Localization.T("alerts.updated");
                AlertsChanged?.Invoke();
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "set alert state failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
        }

        private static string Fmt(DateTimeOffset t) => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

        // 변화 종류를 사용자 언어로(ScanDiff.Describe와 같은 change.* 키의 접두어, 끝의 ':' 제거).
        private static string TypeName(ScanChangeType type)
        {
            string key = type switch
            {
                ScanChangeType.NewHost => "change.newhost",
                ScanChangeType.HostOffline => "change.offline",
                ScanChangeType.MacChanged => "change.macchanged",
                ScanChangeType.NewOpenPort => "change.newport",
                ScanChangeType.ProhibitedPort => "change.prohibited",
                ScanChangeType.UnapprovedHost => "change.unapproved",
                ScanChangeType.ApprovedMacMismatch => "change.approvedmac",
                ScanChangeType.HighRisk => "change.highrisk",
                _ => "",
            };
            return key.Length == 0 ? type.ToString() : Localization.T(key).TrimEnd(':').Trim();
        }

        private static string StateName(AlertState state) => state switch
        {
            AlertState.Acknowledged => Localization.T("alerts.state.acked"),
            AlertState.Snoozed => Localization.T("alerts.state.snoozed"),
            AlertState.Resolved => Localization.T("alerts.state.resolved"),
            _ => Localization.T("alerts.state.open"),
        };

        // 그리드 표시용 행. 레코드의 DateTimeOffset을 로컬 시간 문자열로 바꿔 둔다.
        private sealed class ScanRow
        {
            public string Started { get; init; } = "";
            public string Finished { get; init; } = "";
            public string SystemName { get; init; } = "";
            public int Total { get; init; }
            public int Alive { get; init; }
            public int Prohibited { get; init; }
            public string Scheduled { get; init; } = "";

            public static ScanRow From(ScanSummary s) => new()
            {
                Started = Fmt(s.StartedAt),
                Finished = Fmt(s.FinishedAt),
                SystemName = s.SystemName,
                Total = s.Total,
                Alive = s.Alive,
                Prohibited = s.Prohibited,
                Scheduled = s.Scheduled ? "O" : "",
            };
        }

        private sealed class InventoryRow
        {
            public string Ip { get; init; } = "";
            public string Approved { get; init; } = "";
            public string ApprovedMac { get; init; } = "";
            public string Owner { get; init; } = "";
            public string Tags { get; init; } = "";
            public string Note { get; init; } = "";
            public string Risk { get; init; } = "";
            public string FirstSeen { get; init; } = "";
            public string LastSeen { get; init; } = "";
            public string LastAlive { get; init; } = "";
            public string LastName { get; init; } = "";
            public string LastMac { get; init; } = "";
            public string LastVendor { get; init; } = "";
            public string LastPorts { get; init; } = "";
            public int SeenCount { get; init; }

            public static InventoryRow From(HostInventoryEntry h) => new()
            {
                Ip = h.Ip,
                Approved = h.Approved ? "✓" : "",
                ApprovedMac = h.ApprovedMac,
                Owner = h.Owner,
                Tags = h.Tags,
                Note = h.Note,
                Risk = h.RiskScore > 0 ? h.RiskScore.ToString() : "",
                FirstSeen = Fmt(h.FirstSeen),
                LastSeen = Fmt(h.LastSeen),
                LastAlive = h.LastAliveAt is DateTimeOffset alive ? Fmt(alive) : "",
                LastName = h.LastName,
                LastMac = h.LastMac,
                LastVendor = h.LastVendor,
                LastPorts = h.LastPorts,
                SeenCount = h.SeenCount,
            };
        }

        private sealed class AlertRow
        {
            public long Id { get; init; }
            public string State { get; init; } = "";
            public string Type { get; init; } = "";
            public string Ip { get; init; } = "";
            public string Detail { get; init; } = "";
            public string First { get; init; } = "";
            public string Last { get; init; } = "";
            public int Count { get; init; }

            public static AlertRow From(AlertRecord a) => new()
            {
                Id = a.Id,
                State = StateName(a.State) + (a.State == AlertState.Snoozed && a.SnoozeUntil is DateTimeOffset until ? $" → {Fmt(until)}" : ""),
                Type = TypeName(a.Type),
                Ip = a.Ip,
                Detail = a.Detail,
                First = Fmt(a.FirstSeen),
                Last = Fmt(a.LastSeen),
                Count = a.Count,
            };
        }
    }
}
