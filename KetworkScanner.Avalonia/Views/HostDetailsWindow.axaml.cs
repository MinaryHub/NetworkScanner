using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using KetworkScanner.Avalonia.Helpers;
using KetworkScanner.Discovery;
using KetworkScanner.Vulnerability;

namespace KetworkScanner.Avalonia.Views
{
    // IPInfo 한 건의 상세. FindingsJson(엔진이 저장한 Finding 배열)을 풀어 심각도 순으로, FactsJson을 필드 순으로 보여준다.
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
            TbModel.Text = Dash(info.Model);
            TbMac.Text = Dash(info.Macaddr);
            TbVendor.Text = Dash(info.Vendor);
            TbIpv6.Text = Dash(info.Ipv6);
            // DeviceType/OsGuess가 이미 프로브 힌트(DeviceHint/OsHint)를 우선 적용한 값이다.
            TbOs.Text = Dash(info.OsGuess);
            TbDevice.Text = Dash(info.DeviceType);
            TbOsVersion.Text = Dash(info.OsVersion);
            TbSwitchPort.Text = Dash(info.SwitchPort);
            TbPorts.Text = Dash(info.Ports);
            TbService.Text = Dash(info.Service);
            TbSysDescr.Text = Dash(info.SysDescr);
            TbSource.Text = Dash(info.IdentitySource);

            var facts = HostFacts.FromJson(info.Ip, info.FactsJson);
            var factRows = facts.All
                .OrderBy(f => f.Field).ThenByDescending(f => (int)f.Confidence)
                .Select(f => new FactRow(f.Field, f.Value, f.Source, ConfidenceLabel(f.Confidence)))
                .ToList();
            TbFactsHeader.Text = $"{Localization.T("details.facts")} ({factRows.Count})";
            LstFacts.ItemsSource = factRows;

            TbRisk.Text = info.RiskScore.ToString();
            // 위험 색은 표의 행 색과 같은 규칙(StatusKey == "warn")을 따른다.
            TbRisk.Foreground = info.StatusKey == "warn" ? Risk : Ink;
            TbApproved.Text = info.Approved
                ? "✓" + (string.IsNullOrEmpty(info.Owner) ? "" : $"  ({Localization.T("assets.owner")}: {info.Owner})")
                : "-";

            List<FindingRow> rows = ParseFindings(info.FindingsJson);
            TbFindingsHeader.Text = $"{Localization.T("details.findings")} ({rows.Count})";
            LstFindings.ItemsSource = rows.Count > 0
                ? rows
                : new List<FindingRow> { new(Localization.T("details.nofindings"), "", "", "", "", Ink) };
        }

        private static string Dash(string? value) => string.IsNullOrEmpty(value) ? "-" : value;

        private sealed record FactRow(string Field, string Value, string Source, string Confidence);

        // 열거형 이름을 사용자 언어로(severity.*, confidence.* 키).
        private static string SeverityLabel(Severity s) => Localization.T("severity." + s.ToString().ToLowerInvariant());
        private static string ConfidenceLabel(Confidence c) => Localization.T("confidence." + c.ToString().ToLowerInvariant());

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
                        SeverityLabel(f.Severity),
                        f.Detail,
                        f.Reference ?? "",
                        f.Port is int p ? $":{p}  {f.Category}" : f.Category,
                        SeverityBrush(f.Severity)))
                    .ToList();
            }
            catch (Exception ex)
            {
                AppLogger.LogWarn("KetworkScanner", "findings parse failed: " + ex.Message);
                return new List<FindingRow>();
            }
        }

        // 색은 App.axaml의 테마 브러시. 리소스가 없을 때만 같은 값의 기본색을 쓴다.
        private static readonly IBrush Ink = ThemeBrushes.Get("InkBrush", "#FF14202B");
        private static readonly IBrush Risk = ThemeBrushes.Get("RiskBrush", "#FFB91C1C");
        private static readonly IBrush Warn = ThemeBrushes.Get("WarnBrush", "#FFB45309");
        private static readonly IBrush Slate = ThemeBrushes.Get("SlateBrush", "#FF4A5B6B");
        private static readonly IBrush Muted = ThemeBrushes.Get("MutedBrush", "#FF8A97A4");

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
