using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace NetworkScanner
{
    // 스캔 결과를 사람이 읽기 좋은 HTML 리포트, 또는 다른 도구와 연동하기 좋은 JSON으로 만든다.
    public static class ReportGenerator
    {
        // facts 열은 이미 JSON 배열 문자열이므로 중첩 문자열이 아닌 배열로 내보낸다.
        private static JsonElement? ParseFacts(string? json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try { return JsonSerializer.Deserialize<JsonElement>(json); } catch (JsonException) { return null; }
        }

        // 다른 시스템 연동/후처리를 위한 JSON 리포트.
        public static string BuildJson(IEnumerable<IPInfo> items, string systemName, string timestamp)
        {
            var report = new
            {
                systemName,
                generatedAt = timestamp,
                hosts = items.Select(i => new
                {
                    ip = i.Ip,
                    alive = i.Alive,
                    status = i.StatusText,
                    name = i.SystemName,
                    deviceType = i.DeviceType,
                    osGuess = i.OsGuess,
                    osVersion = i.OsVersion,
                    model = i.Model,
                    switchPort = i.SwitchPort,
                    ipv6 = i.Ipv6,
                    facts = ParseFacts(i.FactsJson),
                    ports = i.Ports,
                    service = i.Service,
                    mac = i.Macaddr,
                    vendor = i.Vendor,
                    roundTime = i.RountTime,
                    hasProhibitedPort = i.HasProhibitedPort,
                    description = i.Description,
                    commitDate = i.CommitDate,
                }),
            };
            return JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // 한글이 \uXXXX로 이스케이프되지 않도록
            });
        }

        public static string BuildHtml(IEnumerable<IPInfo> items, string systemName, string timestamp)
        {
            List<IPInfo> all = items.ToList();
            int alive = all.Count(i => i.Alive);
            int prohibited = all.Count(i => i.HasProhibitedPort);

            var sb = new StringBuilder();
            sb.Append($"<!doctype html><html lang=\"{(Localization.IsKorean ? "ko" : "en")}\"><head><meta charset=\"utf-8\">");
            sb.Append($"<title>{Escape(Localization.T("report.title"))}</title><style>");
            sb.Append("body{font-family:-apple-system,'Segoe UI','Malgun Gothic',sans-serif;margin:24px;color:#1b2430;}");
            sb.Append("h1{font-size:20px;} .meta{color:#5b6b7b;margin-bottom:16px;}");
            sb.Append(".cards{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;}");
            sb.Append(".card{border:1px solid #d8e0e8;border-radius:8px;padding:12px 16px;min-width:100px;}");
            sb.Append(".card b{display:block;font-size:24px;} .warn{color:#c0392b;}");
            sb.Append("table{border-collapse:collapse;width:100%;font-size:13px;}");
            sb.Append("th,td{border:1px solid #d8e0e8;padding:6px 8px;text-align:left;}");
            sb.Append("th{background:#f2f6fa;} tr.bad{color:#9aa7b3;} tr.prohib{background:#fdecea;}");
            sb.Append("</style></head><body>");
            sb.Append($"<h1>{Escape(Localization.T("report.title"))}</h1>");
            sb.Append($"<div class=\"meta\">{Escape(Localization.T("report.system"))}: {Escape(systemName)} · {Escape(Localization.T("report.generated"))}: {Escape(timestamp)}</div>");

            sb.Append("<div class=\"cards\">");
            sb.Append($"<div class=\"card\"><b>{all.Count}</b>{Escape(Localization.T("report.total"))}</div>");
            sb.Append($"<div class=\"card\"><b>{alive}</b>{Escape(Localization.T("report.alive"))}</div>");
            sb.Append($"<div class=\"card{(prohibited > 0 ? " warn" : "")}\"><b>{prohibited}</b>{Escape(Localization.T("report.prohibited"))}</div>");
            sb.Append("</div>");

            sb.Append("<table><thead><tr>");
            foreach (string h in new[] { "col.status", "col.ip", "col.name", "col.type", "col.os", "col.ports", "col.service", "col.mac", "col.vendor", "col.rtt", "col.note" }.Select(Localization.T))
                sb.Append($"<th>{Escape(h)}</th>");
            sb.Append("</tr></thead><tbody>");

            foreach (IPInfo i in all)
            {
                string cls = i.HasProhibitedPort ? "prohib" : (i.Alive ? "" : "bad");
                sb.Append($"<tr class=\"{cls}\">");
                sb.Append($"<td>{Escape(i.StatusText)}</td>");
                sb.Append($"<td>{Escape(i.Ip)}</td>");
                sb.Append($"<td>{Escape(i.SystemName)}</td>");
                sb.Append($"<td>{Escape(i.DeviceType)}</td>");
                sb.Append($"<td>{Escape(i.OsGuess)}</td>");
                sb.Append($"<td>{Escape(i.Ports)}</td>");
                sb.Append($"<td>{Escape(i.Service)}</td>");
                sb.Append($"<td>{Escape(i.Macaddr)}</td>");
                sb.Append($"<td>{Escape(i.Vendor)}</td>");
                sb.Append($"<td>{Escape(i.RountTime)}</td>");
                sb.Append($"<td>{Escape(i.Description)}</td>");
                sb.Append("</tr>");
            }

            sb.Append("</tbody></table></body></html>");
            return sb.ToString();
        }

        private static string Escape(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }
    }
}
