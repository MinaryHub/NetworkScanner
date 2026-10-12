using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using NetworkScanner.Vulnerability;

namespace NetworkScanner.Avalonia.Views
{
    // IPInfo 한 건의 상세. FindingsJson(엔진이 저장한 Finding 배열)을 풀어 심각도 순으로 보여준다.
    public partial class HostDetailsWindow : Window
    {
        public HostDetailsWindow()
        {
            InitializeComponent();
        }

        public void Load(IPInfo info)
        {
            TbIp.Text = info.Ip;
            TbName.Text = string.IsNullOrEmpty(info.SystemName) ? "" : $"{info.SystemName}  ·  {info.Vendor}";
            TbSysDescr.Text = string.IsNullOrEmpty(info.SysDescr) ? "-" : info.SysDescr;
            TbSource.Text = string.IsNullOrEmpty(info.IdentitySource) ? "-" : info.IdentitySource;
            TbOs.Text = string.IsNullOrEmpty(info.OsHint) ? info.OsGuess : info.OsHint;
            TbDevice.Text = string.IsNullOrEmpty(info.DeviceHint) ? info.DeviceType : info.DeviceHint;
            TbOsVersion.Text = string.IsNullOrEmpty(info.OsVersion) ? "-" : info.OsVersion;
            TbSwitchPort.Text = string.IsNullOrEmpty(info.SwitchPort) ? "-" : info.SwitchPort;
            var facts = NetworkScanner.Discovery.HostFacts.FromJson(info.Ip, info.FactsJson);
            var factRows = facts.All
                .OrderBy(f => f.Field).ThenByDescending(f => (int)f.Confidence)
                .Select(f => new FactRow(f.Field, f.Value, f.Source, f.Confidence.ToString()))
                .ToList();
            TbFactsHeader.Text = $"{Localization.T("details.facts")} ({factRows.Count})";
            LstFacts.ItemsSource = factRows;
            TbRisk.Text = info.RiskScore.ToString();
            TbRisk.Foreground = info.RiskScore >= 40 ? Risk : Ink;
            TbApproved.Text = info.Approved
                ? "✓" + (string.IsNullOrEmpty(info.Owner) ? "" : $"  ({Localization.T("assets.owner")}: {info.Owner})")
                : "-";

            List<FindingRow> rows = ParseFindings(info.FindingsJson);
            TbFindingsHeader.Text = $"{Localization.T("details.findings")} ({rows.Count})";
            LstFindings.ItemsSource = rows.Count > 0
                ? rows
                : new List<FindingRow> { new(Localization.T("details.nofindings"), "", "", "", "", Ink) };
        }

        private sealed record FactRow(string Field, string Value, string Source, string Confidence);

        // 심각도 높은 것부터. 잘못된 JSON은 빈 목록으로 취급한다(상세 창이 열리지 않는 것보다 낫다).
        private static List<FindingRow> ParseFindings(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return new List<FindingRow>();
            try
            {
                List<Finding>? findings = JsonSerializer.Deserialize<List<Finding>>(json);
                if (findings == null) return new List<FindingRow>();
                return findings
                    .OrderByDescending(f => f.Severity)
                    .Select(f => new FindingRow(
                        f.Title,
                        f.Severity.ToString(),
                        f.Detail,
                        f.Reference ?? "",
                        f.Port is int p ? $":{p}  {f.Category}" : f.Category,
                        SeverityBrush(f.Severity)))
                    .ToList();
            }
            catch (Exception ex)
            {
                AppLogger.LogWarn("NetworkScanner", "findings parse failed: " + ex.Message);
                return new List<FindingRow>();
            }
        }

        private static readonly IBrush Ink = new SolidColorBrush(Color.Parse("#FF14202B"));
        private static readonly IBrush Risk = new SolidColorBrush(Color.Parse("#FFB91C1C"));
        private static readonly IBrush Warn = new SolidColorBrush(Color.Parse("#FFB45309"));
        private static readonly IBrush Slate = new SolidColorBrush(Color.Parse("#FF4A5B6B"));
        private static readonly IBrush Muted = new SolidColorBrush(Color.Parse("#FF8A97A4"));

        private static IBrush SeverityBrush(Severity s) => s switch
        {
            Severity.Critical or Severity.High => Risk,
            Severity.Medium => Warn,
            Severity.Low => Slate,
            _ => Muted,
        };

        private void BtnClose_Click(object? sender, RoutedEventArgs e) => Close();

        // 목록 바인딩용 행. Brush는 심각도 배지 색.
        public sealed record FindingRow(string Title, string Severity, string Detail, string Reference, string Where, IBrush Brush)
        {
            public bool HasReference => Reference.Length > 0;
        }
    }
}
