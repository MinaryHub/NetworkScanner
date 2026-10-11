using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using NetworkScanner.Avalonia.Helpers;
using NetworkScanner.History;

namespace NetworkScanner.Avalonia.Views
{
    /// <summary>
    /// SQLite 스캔 이력(ScanHistoryStore)을 보여주는 화면. 읽기 전용이며 삭제는 Prune 버튼으로만 한다.
    /// 그리드에는 표시용 문자열 행만 바인딩한다(시각은 로컬 시간으로 변환).
    /// </summary>
    public partial class HistoryView : UserControl
    {
        private const int PruneDays = 90;
        private ScanHistoryStore? _history;

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
            if (!available) TbMsg.Text = Localization.T("history.unavailable");
        }

        public void Refresh()
        {
            if (_history == null)
            {
                TbMsg.Text = Localization.T("history.unavailable");
                return;
            }

            try
            {
                DgScans.ItemsSource = _history.ListScans(100).Select(ScanRow.From).ToList();
                DgInventory.ItemsSource = _history.GetInventory().Select(InventoryRow.From).ToList();
                TbMsg.Text = "";
            }
            catch (Exception ex)
            {
                AppLogger.LogError("NetworkScanner", "history read failed", ex);
                TbMsg.Text = string.Format(Localization.T("history.loadfailed"), ex.Message);
            }
        }

        private void BtnRefresh_Click(object? sender, RoutedEventArgs e) => Refresh();

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

        private static string Fmt(DateTimeOffset t) => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

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
    }
}
