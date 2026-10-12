using System;
using System.Collections.Generic;
using System.Globalization;
using Avalonia.Controls;

namespace NetworkScanner.Avalonia.Helpers
{
    // DataGrid의 사용자 조절 컬럼 너비를 문자열로 직렬화/복원한다.
    // 키는 컬럼의 Tag("ip", "model" …)라서 컬럼이 추가되거나 순서가 바뀌어도 저장된 너비가 섞이지 않는다.
    // 형식: "tag=width;tag=width;…". 예전 버전의 인덱스 기준 "w,w,w" 형식은 무시한다(기본 너비로 시작).
    internal static class ColumnLayout
    {
        public static string Serialize(DataGrid grid)
        {
            var parts = new List<string>();
            foreach (DataGridColumn c in grid.Columns)
            {
                if (c.Tag is not string tag || tag.Length == 0) continue;
                double w = c.ActualWidth;
                if (double.IsNaN(w) || w <= 0) w = c.Width.IsAbsolute ? c.Width.Value : 0;
                if (w <= 0) continue;
                parts.Add(tag + "=" + ((int)w).ToString(CultureInfo.InvariantCulture));
            }
            return string.Join(";", parts);
        }

        public static void Apply(DataGrid grid, string saved)
        {
            Dictionary<string, int> widths = Parse(saved);
            if (widths.Count == 0) return;

            foreach (DataGridColumn c in grid.Columns)
            {
                if (c.Tag is string tag && widths.TryGetValue(tag, out int w))
                    c.Width = new DataGridLength(w);
            }
        }

        // "tag=width;…"만 받아들인다. '='가 없는 항목(옛 인덱스 형식)은 건너뛴다.
        internal static Dictionary<string, int> Parse(string? saved)
        {
            var result = new Dictionary<string, int>(StringComparer.Ordinal);
            if (string.IsNullOrWhiteSpace(saved)) return result;

            foreach (string part in saved.Split(';'))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0) continue;
                string tag = part.Substring(0, eq).Trim();
                if (tag.Length == 0) continue;
                if (int.TryParse(part.AsSpan(eq + 1).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int w) && w > 0)
                    result[tag] = w;
            }
            return result;
        }
    }
}
