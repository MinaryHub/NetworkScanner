using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PdfSharp;
using PdfSharp.Drawing;
using PdfSharp.Pdf;

namespace KetworkScanner.Reports
{
    // 스캔 결과를 A4 PDF 리포트로 만든다. 폰트는 임베드된 나눔고딕이라 OS 설치 폰트와 무관하게 한글이 나온다.
    // 구성: 제목/메타 → 요약 타일(전체/정상/위험) → (선택) 변화 목록 → 결과 표(페이지마다 헤더 반복) → 모든 페이지에 "page N / M".
    public static class PdfReport
    {
        // 프로젝트 팔레트("Harbor Ops")
        private static readonly XColor Ink = XColor.FromArgb(0x14, 0x20, 0x2B);
        private static readonly XColor Slate = XColor.FromArgb(0x4A, 0x5B, 0x6B);
        private static readonly XColor Line = XColor.FromArgb(0xD9, 0xE0, 0xE7);
        private static readonly XColor Teal = XColor.FromArgb(0x0F, 0x76, 0x6E);
        private static readonly XColor Zebra = XColor.FromArgb(0xF4, 0xF6, 0xF8);
        private static readonly XColor HeaderFill = XColor.FromArgb(0xEE, 0xF2, 0xF5);
        private static readonly XColor RiskyFill = XColor.FromArgb(0xFD, 0xEC, 0xEA);
        private static readonly XColor StatusUp = XColor.FromArgb(0x15, 0x80, 0x3D);
        private static readonly XColor StatusRisky = XColor.FromArgb(0xB9, 0x1C, 0x1C);
        private static readonly XColor StatusDown = XColor.FromArgb(0x8A, 0x97, 0xA4);

        private const double MarginMm = 18;

        // 표 컬럼: 로컬라이즈 키, 상대 폭, 오른쪽 정렬 여부, 값 추출기, 잘리면 안 되는 대표 값(최소 폭 계산용)
        private sealed record Column(string Key, double Weight, bool AlignRight, Func<IPInfo, string> Value, string MinSample = "");

        private static readonly Column[] Columns =
        {
            new("col.status", 6, false, i => i.StatusText),
            new("col.ip", 8, false, i => i.Ip, "255.255.255.255"),
            new("col.name", 11, false, i => i.SystemName),
            new("col.type", 7, false, i => i.DeviceType),
            new("col.os", 7, false, i => i.OsGuess),
            new("col.ports", 12, false, i => i.Ports),
            new("col.service", 12, false, i => i.Service),
            new("col.mac", 10, false, i => i.Macaddr, "00:00:00:00:00:00"),
            new("col.vendor", 9, false, i => i.Vendor),
            new("col.rtt", 5, true, i => i.RountTime, "9999"),
        };

        public static byte[] Build(IReadOnlyList<IPInfo> items, string systemName, string generatedAt, PdfReportOptions? options = null)
        {
            ArgumentNullException.ThrowIfNull(items);
            options ??= new PdfReportOptions();
            NanumFontResolver.EnsureRegistered();

            using var doc = new PdfDocument();
            doc.Info.Title = Localization.T("report.title");
            doc.Info.Creator = "KetworkScanner";
            doc.Info.Subject = SanitizeText(systemName);

            using (var page = new PageWriter(doc, options.Landscape))
            {
                DrawTitle(page, systemName, generatedAt, options.Subtitle);
                DrawSummary(page, items);
                if (options.Changes is { Count: > 0 })
                    BuildChangesSection(page, options.Changes);
                DrawTable(page, items);
            }
            DrawFooters(doc);

            using var ms = new MemoryStream();
            doc.Save(ms, false);
            return ms.ToArray();
        }

        // Build 결과를 파일로 저장한다. 렌더링은 CPU 작업이라 스레드풀에서 돌리고, 폴더가 없으면 만든다.
        public static async Task SaveAsync(string path, IReadOnlyList<IPInfo> items, string systemName, string generatedAt,
            PdfReportOptions? options = null, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            byte[] bytes = await Task.Run(() => Build(items, systemName, generatedAt, options), cancellationToken).ConfigureAwait(false);
            string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            await File.WriteAllBytesAsync(path, bytes, cancellationToken).ConfigureAwait(false);
        }

        // ---- 섹션 ----

        private static void DrawTitle(PageWriter w, string systemName, string generatedAt, string? subtitle)
        {
            w.DrawText("KetworkScanner", w.Font(11, bold: true), Teal, w.Left, w.Y, w.Width);
            w.Y += 15;
            w.DrawText(Localization.T("report.title"), w.Font(18, bold: true), Ink, w.Left, w.Y, w.Width);
            w.Y += 24;
            if (!string.IsNullOrWhiteSpace(subtitle))
            {
                w.DrawText(subtitle, w.Font(10), Slate, w.Left, w.Y, w.Width);
                w.Y += 14;
            }
            string meta = $"{Localization.T("report.system")}: {SanitizeText(systemName)}     {Localization.T("report.generated")}: {SanitizeText(generatedAt)}";
            w.DrawText(meta, w.Font(9), Slate, w.Left, w.Y, w.Width);
            w.Y += 14;
            w.Gfx.DrawLine(new XPen(Teal, 1.5), w.Left, w.Y, w.Left + w.Width, w.Y);
            w.Y += 12;
        }

        private static void DrawSummary(PageWriter w, IReadOnlyList<IPInfo> items)
        {
            int total = items.Count;
            int alive = items.Count(i => i.Alive);
            int risky = items.Count(i => i.HasProhibitedPort);

            (string label, int value, XColor color)[] tiles =
            {
                (Localization.T("report.total"), total, Ink),
                (Localization.T("report.alive"), alive, StatusUp),
                (Localization.T("report.prohibited"), risky, risky > 0 ? StatusRisky : Ink),
            };

            const double tileW = 110, tileH = 44, gap = 10;
            double x = w.Left;
            var pen = new XPen(Line, 0.75);
            foreach (var (label, value, color) in tiles)
            {
                var rect = new XRect(x, w.Y, tileW, tileH);
                w.Gfx.DrawRoundedRectangle(pen, XBrushes.White, rect, new XSize(6, 6));
                w.DrawText(label, w.Font(8), Slate, x + 10, w.Y + 7, tileW - 20);
                w.DrawText(value.ToString(), w.Font(16, bold: true), color, x + 10, w.Y + 19, tileW - 20);
                x += tileW + gap;
            }
            w.Y += tileH + 16;
        }

        // 직전 스캔 대비 변화를 불릿 목록으로 그린다. 보안 관련(MAC 변경/위험 포트)은 붉게 강조한다.
        internal static void BuildChangesSection(PageWriter w, IReadOnlyList<ScanChange> changes)
        {
            string heading = Localization.IsKorean ? "마지막 스캔 이후 변화" : "Changes since last scan";
            XFont headFont = w.Font(11, bold: true);
            XFont bodyFont = w.Font(9);
            double lineH = 13;

            w.EnsureSpace(20 + lineH);
            w.DrawText($"{heading} ({changes.Count})", headFont, Ink, w.Left, w.Y, w.Width);
            w.Y += 18;

            const double bullet = 12;
            foreach (ScanChange c in changes)
            {
                XColor color = ScanDiff.IsSecurityRelevant(c.Type) ? StatusRisky : Ink;
                List<string> lines = w.Wrap(SanitizeText(ScanDiff.Describe(c)), bodyFont, w.Width - bullet);
                w.EnsureSpace(lineH * lines.Count);
                w.DrawText("•", bodyFont, color, w.Left, w.Y, bullet);
                foreach (string line in lines)
                {
                    w.DrawText(line, bodyFont, color, w.Left + bullet, w.Y, w.Width - bullet);
                    w.Y += lineH;
                }
            }
            w.Y += 10;
        }

        private static void DrawTable(PageWriter w, IReadOnlyList<IPInfo> items)
        {
            // 세로 용지는 폭이 좁아 글자를 줄여 넣는다.
            double fontSize = w.Landscape ? 8 : 6.5;
            double rowH = Math.Round(fontSize * 1.8);
            double pad = 4;
            XFont cellFont = w.Font(fontSize);
            XFont headFont = w.Font(fontSize, bold: true);

            double[] widths = ComputeColumnWidths(w, headFont, cellFont, pad);
            var hairline = new XPen(Line, 0.5);

            void DrawHeader()
            {
                w.Gfx.DrawRectangle(new XSolidBrush(HeaderFill), new XRect(w.Left, w.Y, w.Width, rowH));
                double x = w.Left;
                for (int c = 0; c < Columns.Length; c++)
                {
                    w.DrawCell(Localization.T(Columns[c].Key), headFont, Slate, x + pad, w.Y, widths[c] - pad * 2, rowH, Columns[c].AlignRight);
                    x += widths[c];
                }
                w.Gfx.DrawLine(new XPen(Teal, 1), w.Left, w.Y + rowH, w.Left + w.Width, w.Y + rowH);
                w.Y += rowH;
            }

            w.EnsureSpace(rowH * 3); // 헤더만 남고 페이지가 끝나지 않도록 최소 두 줄 공간을 확보
            DrawHeader();

            for (int r = 0; r < items.Count; r++)
            {
                IPInfo item = items[r];
                if (w.EnsureSpace(rowH)) DrawHeader();

                XColor? fill = item.HasProhibitedPort ? RiskyFill : (r % 2 == 1 ? Zebra : null);
                if (fill is { } f)
                    w.Gfx.DrawRectangle(new XSolidBrush(f), new XRect(w.Left, w.Y, w.Width, rowH));

                XColor textColor = item.Alive ? Ink : Slate;
                XColor statusColor = item.StatusKey switch
                {
                    "good" => StatusUp,
                    "warn" => StatusRisky,
                    _ => StatusDown,
                };

                double x = w.Left;
                for (int c = 0; c < Columns.Length; c++)
                {
                    XColor color = c == 0 ? statusColor : textColor;
                    XFont font = c == 0 ? headFont : cellFont;
                    w.DrawCell(SanitizeText(Columns[c].Value(item)), font, color, x + pad, w.Y, widths[c] - pad * 2, rowH, Columns[c].AlignRight);
                    x += widths[c];
                }
                w.Gfx.DrawLine(hairline, w.Left, w.Y + rowH, w.Left + w.Width, w.Y + rowH);
                w.Y += rowH;
            }
        }

        // 상대 폭으로 나누되, 헤더 글자나 IP/MAC 같은 대표 값이 잘리는 컬럼은 최소 폭을 보장하고 나머지 컬럼이 그만큼 양보한다.
        private static double[] ComputeColumnWidths(PageWriter w, XFont headFont, XFont cellFont, double pad)
        {
            double totalWeight = Columns.Sum(c => c.Weight);
            double[] widths = Columns.Select(c => w.Width * c.Weight / totalWeight).ToArray();
            double[] min = Columns.Select(c => Math.Max(
                w.Measure(Localization.T(c.Key), headFont),
                c.MinSample.Length == 0 ? 0 : w.Measure(c.MinSample, cellFont)) + pad * 2 + 1).ToArray();
            var fixedCols = new bool[Columns.Length];

            for (int pass = 0; pass < Columns.Length; pass++)
            {
                bool changed = false;
                for (int c = 0; c < Columns.Length; c++)
                {
                    if (fixedCols[c] || widths[c] >= min[c]) continue;
                    widths[c] = min[c];
                    fixedCols[c] = true;
                    changed = true;
                }
                if (!changed) break;

                double fixedTotal = 0, flexWeight = 0;
                for (int c = 0; c < Columns.Length; c++)
                {
                    if (fixedCols[c]) fixedTotal += widths[c]; else flexWeight += Columns[c].Weight;
                }
                double remaining = Math.Max(0, w.Width - fixedTotal);
                if (flexWeight <= 0) break;
                for (int c = 0; c < Columns.Length; c++)
                    if (!fixedCols[c]) widths[c] = remaining * Columns[c].Weight / flexWeight;
            }
            return widths;
        }

        // 페이지 수는 본문을 다 그린 뒤에야 확정되므로 푸터는 마지막에 모든 페이지를 돌며 그린다.
        private static void DrawFooters(PdfDocument doc)
        {
            int count = doc.PageCount;
            var font = new XFont(NanumFontResolver.FamilyName, 8, XFontStyleEx.Regular);
            var brush = new XSolidBrush(Slate);
            double margin = XUnit.FromMillimeter(MarginMm).Point;
            for (int i = 0; i < count; i++)
            {
                PdfPage page = doc.Pages[i];
                using XGraphics gfx = XGraphics.FromPdfPage(page);
                double width = page.Width.Point, height = page.Height.Point;
                double y = height - margin + 8;
                gfx.DrawLine(new XPen(Line, 0.5), margin, y - 4, width - margin, y - 4);
                gfx.DrawString(Localization.T("report.title"), font, brush, new XRect(margin, y, width - margin * 2, 12), XStringFormats.CenterLeft);
                gfx.DrawString($"page {i + 1} / {count}", font, brush, new XRect(margin, y, width - margin * 2, 12), XStringFormats.CenterRight);
            }
        }

        // 폰트에 없는 글자(이모지 등 서로게이트 쌍), 제어 문자를 걸러 .notdef 사각형이 찍히지 않게 한다.
        public static string SanitizeText(string? text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            var sb = new StringBuilder(text.Length);
            foreach (char ch in text)
            {
                if (char.IsSurrogate(ch)) continue;
                if (ch == '⚠') { sb.Append('!'); continue; } // ⚠는 나눔고딕에 없다
                sb.Append(char.IsControl(ch) ? ' ' : ch);
            }
            return sb.ToString();
        }

        // 한 문서의 현재 페이지/커서를 들고 있는 작은 레이아웃 도우미.
        internal sealed class PageWriter : IDisposable
        {
            private readonly PdfDocument _doc;
            private readonly Dictionary<(double, bool), XFont> _fonts = new();
            private readonly double _margin = XUnit.FromMillimeter(MarginMm).Point;
            private XGraphics? _gfx;

            public bool Landscape { get; }
            public double Y { get; set; }
            public double Left => _margin;
            public double Width { get; private set; }
            public double Bottom { get; private set; }
            public XGraphics Gfx => _gfx ?? throw new InvalidOperationException("No page started.");

            public PageWriter(PdfDocument doc, bool landscape)
            {
                _doc = doc;
                Landscape = landscape;
                NewPage();
            }

            public XFont Font(double size, bool bold = false)
            {
                if (!_fonts.TryGetValue((size, bold), out XFont? font))
                {
                    font = new XFont(NanumFontResolver.FamilyName, size, bold ? XFontStyleEx.Bold : XFontStyleEx.Regular);
                    _fonts[(size, bold)] = font;
                }
                return font;
            }

            public void NewPage()
            {
                _gfx?.Dispose();
                PdfPage page = _doc.AddPage();
                page.Size = PageSize.A4;
                page.Orientation = Landscape ? PageOrientation.Landscape : PageOrientation.Portrait;
                _gfx = XGraphics.FromPdfPage(page);
                Width = page.Width.Point - _margin * 2;
                Bottom = page.Height.Point - _margin - 14; // 푸터 영역
                Y = _margin;
            }

            // 남은 공간이 부족하면 새 페이지를 시작하고 true를 돌려준다(표 헤더 재출력 판단용).
            public bool EnsureSpace(double height)
            {
                if (Y + height <= Bottom) return false;
                NewPage();
                return true;
            }

            public double Measure(string text, XFont font) => Gfx.MeasureString(text, font).Width;

            // 한 줄 텍스트. 폭을 넘으면 말줄임표로 자른다.
            public void DrawText(string text, XFont font, XColor color, double x, double y, double maxWidth)
            {
                string fitted = Fit(text, font, maxWidth);
                if (fitted.Length == 0) return;
                Gfx.DrawString(fitted, font, new XSolidBrush(color), new XRect(x, y, maxWidth, font.Height), XStringFormats.TopLeft);
            }

            // 표 셀: 세로 가운데 정렬, 폭을 넘으면 말줄임표.
            public void DrawCell(string text, XFont font, XColor color, double x, double y, double width, double height, bool alignRight)
            {
                string fitted = Fit(text, font, width);
                if (fitted.Length == 0) return;
                Gfx.DrawString(fitted, font, new XSolidBrush(color), new XRect(x, y, width, height),
                    alignRight ? XStringFormats.CenterRight : XStringFormats.CenterLeft);
            }

            // 이진 탐색으로 maxWidth 안에 들어가는 가장 긴 접두사 + "…"를 찾는다.
            public string Fit(string text, XFont font, double maxWidth)
            {
                if (text.Length == 0 || Measure(text, font) <= maxWidth) return text;
                const string ellipsis = "…";
                int lo = 0, hi = text.Length - 1;
                while (lo < hi)
                {
                    int mid = (lo + hi + 1) / 2;
                    if (Measure(text[..mid] + ellipsis, font) <= maxWidth) lo = mid; else hi = mid - 1;
                }
                return lo == 0 ? "" : text[..lo].TrimEnd() + ellipsis;
            }

            // 단어 단위 줄바꿈. 한 단어가 폭보다 길면 글자 단위로 끊는다.
            public List<string> Wrap(string text, XFont font, double width)
            {
                var lines = new List<string>();
                var current = new StringBuilder();
                foreach (string word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    string candidate = current.Length == 0 ? word : current + " " + word;
                    if (Measure(candidate, font) <= width)
                    {
                        current.Clear().Append(candidate);
                        continue;
                    }
                    if (current.Length > 0) { lines.Add(current.ToString()); current.Clear(); }
                    string rest = word;
                    while (rest.Length > 0 && Measure(rest, font) > width)
                    {
                        int n = 1;
                        while (n < rest.Length && Measure(rest[..(n + 1)], font) <= width) n++;
                        lines.Add(rest[..n]);
                        rest = rest[n..];
                    }
                    current.Append(rest);
                }
                if (current.Length > 0) lines.Add(current.ToString());
                if (lines.Count == 0) lines.Add("");
                return lines;
            }

            public void Dispose()
            {
                _gfx?.Dispose();
                _gfx = null;
            }
        }
    }
}
