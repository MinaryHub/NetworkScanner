using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using NetworkScanner.History;

namespace NetworkScanner.Alerts
{
    // 점검 시간대(그 시간엔 알림을 보내지 않고 기록만). "Mon-Fri 22:00-06:00" / "Sat,Sun" / "* 12:00-13:00" 형식.
    public sealed record MaintenanceWindow(DayOfWeek[] Days, TimeSpan Start, TimeSpan End)
    {
        public bool Contains(DateTime local)
        {
            TimeSpan t = local.TimeOfDay;
            if (Start == End) return Days.Contains(local.DayOfWeek);                    // 하루 종일
            if (Start < End) return Days.Contains(local.DayOfWeek) && t >= Start && t < End;
            // 자정을 넘기는 창: 시작 요일 밤 + 다음 날 새벽
            bool lateToday = Days.Contains(local.DayOfWeek) && t >= Start;
            bool earlyNext = Days.Contains(local.AddDays(-1).DayOfWeek) && t < End;
            return lateToday || earlyNext;
        }

        private static readonly Dictionary<string, DayOfWeek> DayNames = new(StringComparer.OrdinalIgnoreCase)
        {
            ["mon"] = DayOfWeek.Monday, ["tue"] = DayOfWeek.Tuesday, ["wed"] = DayOfWeek.Wednesday, ["thu"] = DayOfWeek.Thursday,
            ["fri"] = DayOfWeek.Friday, ["sat"] = DayOfWeek.Saturday, ["sun"] = DayOfWeek.Sunday,
            ["월"] = DayOfWeek.Monday, ["화"] = DayOfWeek.Tuesday, ["수"] = DayOfWeek.Wednesday, ["목"] = DayOfWeek.Thursday,
            ["금"] = DayOfWeek.Friday, ["토"] = DayOfWeek.Saturday, ["일"] = DayOfWeek.Sunday,
        };

        // 한 줄("Mon-Fri 22:00-06:00")을 파싱한다. 요일 생략/"*"는 매일, 시간 생략은 하루 종일.
        public static bool TryParse(string text, out MaintenanceWindow? window)
        {
            window = null;
            if (string.IsNullOrWhiteSpace(text)) return false;
            string[] parts = text.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string dayPart = parts.Length > 0 && !parts[0].Contains(':') ? parts[0] : "*";
            string? timePart = parts.FirstOrDefault(p => p.Contains(':'));

            var days = new List<DayOfWeek>();
            if (dayPart == "*" || dayPart.Equals("daily", StringComparison.OrdinalIgnoreCase) || dayPart == "매일")
            {
                days.AddRange(Enum.GetValues<DayOfWeek>());
            }
            else
            {
                foreach (string token in dayPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] range = token.Split('-');
                    if (range.Length == 2)
                    {
                        if (!DayNames.TryGetValue(range[0].Trim(), out var a) || !DayNames.TryGetValue(range[1].Trim(), out var b)) return false;
                        for (int d = (int)a; ; d = (d + 1) % 7) { days.Add((DayOfWeek)d); if (d == (int)b) break; }
                    }
                    else if (DayNames.TryGetValue(token.Trim(), out var single)) days.Add(single);
                    else return false;
                }
            }

            TimeSpan start = TimeSpan.Zero, end = TimeSpan.Zero;
            if (timePart != null)
            {
                string[] t = timePart.Split('-');
                if (t.Length != 2) return false;
                if (!TimeSpan.TryParseExact(t[0].Trim(), @"h\:mm", CultureInfo.InvariantCulture, out start)
                    && !TimeSpan.TryParseExact(t[0].Trim(), @"hh\:mm", CultureInfo.InvariantCulture, out start)) return false;
                if (!TimeSpan.TryParseExact(t[1].Trim(), @"h\:mm", CultureInfo.InvariantCulture, out end)
                    && !TimeSpan.TryParseExact(t[1].Trim(), @"hh\:mm", CultureInfo.InvariantCulture, out end)) return false;
                if (end == TimeSpan.FromHours(24)) end = TimeSpan.Zero;
            }
            window = new MaintenanceWindow(days.Distinct().ToArray(), start, end);
            return true;
        }

        // 여러 줄/세미콜론 구분 문자열 → 창 목록. 잘못된 줄은 invalid로 돌려준다.
        public static (List<MaintenanceWindow> Windows, List<string> Invalid) ParseList(string? text)
        {
            var ok = new List<MaintenanceWindow>();
            var bad = new List<string>();
            if (string.IsNullOrWhiteSpace(text)) return (ok, bad);
            foreach (string line in text.Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (TryParse(line, out var w) && w != null) ok.Add(w); else bad.Add(line.Trim());
            }
            return (ok, bad);
        }
    }

    // 알림 처리 결과. ToNotify만 외부 채널로 보내고, 나머지는 기록만 남는다.
    public sealed class AlertOutcome
    {
        public List<AlertRecord> ToNotify { get; } = new();
        public List<AlertRecord> Suppressed { get; } = new();   // 확인/스누즈/재알림 대기 중이라 보내지 않음
        public List<AlertRecord> Active { get; } = new();       // 이번 스캔에서 관찰된 모든 알림
        public int Resolved { get; set; }
        public bool InMaintenance { get; set; }
        public IReadOnlyList<ScanChange> ChangesToNotify { get; set; } = Array.Empty<ScanChange>();
    }

    // 변화 목록을 알림으로 바꾼다: 중복 누적, 확인/스누즈 존중, 점검 시간대 억제, 일정 시간 지나면 재알림, 조건 사라지면 자동 해결.
    public sealed class AlertManager
    {
        private readonly ScanHistoryStore _store;
        private readonly AlertSettings _settings;
        private readonly IReadOnlyList<MaintenanceWindow> _windows;

        public AlertManager(ScanHistoryStore store, AlertSettings settings)
        {
            _store = store;
            _settings = settings;
            _windows = MaintenanceWindow.ParseList(settings.MaintenanceWindows).Windows;
        }

        public bool IsInMaintenance(DateTime localNow) => _windows.Any(w => w.Contains(localNow));

        public AlertOutcome Process(IReadOnlyList<ScanChange> changes, DateTimeOffset now, bool securityOnly)
        {
            var outcome = new AlertOutcome { InMaintenance = IsInMaintenance(now.LocalDateTime) };
            var activeKeys = new List<string>();
            var notifyChanges = new List<ScanChange>();
            var notifiedIds = new List<long>();

            foreach (ScanChange c in changes)
            {
                if (securityOnly && !ScanDiff.IsSecurityRelevant(c.Type)) continue;

                string key = ScanDiff.AlertKey(c);
                activeKeys.Add(key);
                AlertRecord rec = _store.UpsertAlert(key, c.Type, c.Ip, c.Detail, now);
                outcome.Active.Add(rec);

                bool suppressed = rec.State == AlertState.Acknowledged
                    || (rec.State == AlertState.Snoozed && rec.SnoozeUntil.HasValue && rec.SnoozeUntil.Value > now)
                    || outcome.InMaintenance
                    || (rec.LastNotifiedAt.HasValue && _settings.RenotifyAfterHours > 0
                        && (now - rec.LastNotifiedAt.Value).TotalHours < _settings.RenotifyAfterHours)
                    || (rec.LastNotifiedAt.HasValue && _settings.RenotifyAfterHours <= 0);

                if (suppressed)
                {
                    outcome.Suppressed.Add(rec);
                }
                else
                {
                    outcome.ToNotify.Add(rec);
                    notifyChanges.Add(c);
                    notifiedIds.Add(rec.Id);
                }
            }

            if (notifiedIds.Count > 0) _store.MarkAlertsNotified(notifiedIds, now);
            outcome.Resolved = _store.ResolveAlertsNotIn(activeKeys, ScanDiff.ResolvableTypes);
            outcome.ChangesToNotify = notifyChanges;
            return outcome;
        }
    }

    public sealed class AlertSettings
    {
        // 같은 알림이 계속 열려 있을 때 몇 시간마다 다시 보낼지(0 = 처음 한 번만).
        public int RenotifyAfterHours { get; set; } = 24;
        // 점검 시간대 목록. 예: "Mon-Fri 22:00-06:00; Sat,Sun"
        public string MaintenanceWindows { get; set; } = "";
    }
}
