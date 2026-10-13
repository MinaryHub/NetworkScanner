using System.Globalization;
using System.Net;
using System.Text;

namespace KetworkScanner.Collector;

// 서버 렌더링 HTML 대시보드. JS 없이 인라인 CSS만 쓰고, 출력되는 모든 값은 HTML 이스케이프한다.
public static class Dashboard
{
    private const string Css = """
        :root{--ink:#14202B;--bg:#F4F6F8;--navy:#0F1B2D;--teal:#0F766E;--up:#15803D;--risk:#B91C1C;--line:#D9E0E7;--tint:#FDECEA}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.4}
        header{background:var(--navy);color:#fff;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px}
        header a{color:#fff;text-decoration:none;font-weight:600;font-size:16px}
        header .sub{opacity:.75;font-size:12px}
        header form{margin:0}
        header button{background:transparent;color:#fff;border:1px solid rgba(255,255,255,.4);padding:4px 10px;font:inherit;font-size:12px;cursor:pointer}
        main{max-width:1200px;margin:0 auto;padding:24px 16px}
        h1{font-size:20px;margin:0 0 16px}
        h2{font-size:16px;margin:28px 0 10px}
        .crumbs{font-size:12px;margin-bottom:12px}
        .crumbs a{color:var(--teal)}
        .wrap{overflow-x:auto;background:#fff;border:1px solid var(--line)}
        table{width:100%;border-collapse:collapse}
        th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}
        th{color:var(--navy);font-weight:600;font-size:12px;letter-spacing:.02em;text-transform:uppercase}
        tr:last-child td{border-bottom:0}
        td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
        tr.risky td{background:var(--tint)}
        .up{color:var(--up);font-weight:600}
        .risk{color:var(--risk);font-weight:600}
        .muted{color:#6B7A8A}
        a{color:var(--teal)}
        .empty{padding:24px;color:#6B7A8A;background:#fff;border:1px solid var(--line)}
        form.login{max-width:380px;margin:60px auto;background:#fff;border:1px solid var(--line);padding:24px}
        form.login label{display:block;font-weight:600;margin-bottom:6px}
        input[type=password]{width:100%;padding:8px;border:1px solid var(--line);font:inherit;margin-bottom:12px}
        form.login button{background:var(--teal);color:#fff;border:0;padding:8px 14px;font:inherit;cursor:pointer}
        .err{color:var(--risk);margin-bottom:12px}
        """;

    public static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static string Index(IReadOnlyList<SiteSummary> sites, Principal who)
    {
        var sb = new StringBuilder();
        sb.Append("<h1>Sites</h1>");
        if (sites.Count == 0)
        {
            sb.Append("<div class=\"empty\">No sites yet. Configure a site token and point a scanner at /api/scan.</div>");
        }
        else
        {
            sb.Append("<div class=\"wrap\"><table><thead><tr>")
              .Append("<th>Site</th><th>Last upload</th><th>Last scan</th><th>System</th>")
              .Append("<th class=\"num\">Total</th><th class=\"num\">Alive</th><th class=\"num\">Risky</th><th class=\"num\">High risk</th><th>Report</th>")
              .Append("</tr></thead><tbody>");
            foreach (SiteSummary s in sites)
            {
                ScanSummary? scan = s.LastScan;
                bool risky = scan != null && (scan.Risky > 0 || scan.HighRisk > 0);
                sb.Append(risky ? "<tr class=\"risky\">" : "<tr>");
                if (who.CanView(s.Site))
                    sb.Append("<td><a href=\"/sites/").Append(Uri.EscapeDataString(s.Site)).Append("\">").Append(H(s.Site)).Append("</a></td>");
                else
                    sb.Append("<td>").Append(H(s.Site)).Append("</td>");
                sb.Append("<td>").Append(Time(s.LastUploadAt)).Append("</td>");
                sb.Append("<td>").Append(Time(scan?.ReceivedAt)).Append("</td>");
                sb.Append("<td>").Append(scan == null ? Dash : H(scan.SystemName)).Append("</td>");
                sb.Append(Num(scan?.Total)).Append(Num(scan?.Alive, "up")).Append(Num(scan?.Risky, "risk")).Append(Num(scan?.HighRisk, "risk"));
                if (s.LatestReportId is long rid)
                    sb.Append("<td><a href=\"/reports/").Append(rid.ToString(CultureInfo.InvariantCulture)).Append("\">")
                      .Append(H(s.LatestReportKind?.ToUpperInvariant())).Append("</a></td>");
                else
                    sb.Append("<td>").Append(Dash).Append("</td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table></div>");
        }
        return Layout("Sites", sb.ToString(), who);
    }

    public static string Site(string site, IReadOnlyList<ScanSummary> scans, IReadOnlyList<HostRow> hosts, (long Id, string Kind)? report, Principal who)
    {
        var sb = new StringBuilder();
        sb.Append("<div class=\"crumbs\"><a href=\"/\">Sites</a> / ").Append(H(site)).Append("</div>");
        sb.Append("<h1>").Append(H(site)).Append("</h1>");
        if (report is (long rid, string kind))
            sb.Append("<p>Latest report: <a href=\"/reports/").Append(rid.ToString(CultureInfo.InvariantCulture)).Append("\">")
              .Append(H(kind.ToUpperInvariant())).Append("</a></p>");

        sb.Append("<h2>Recent scans</h2>");
        if (scans.Count == 0)
        {
            sb.Append("<div class=\"empty\">No scans received yet.</div>");
        }
        else
        {
            sb.Append("<div class=\"wrap\"><table><thead><tr><th>Received</th><th>System</th>")
              .Append("<th class=\"num\">Total</th><th class=\"num\">Alive</th><th class=\"num\">Risky</th><th class=\"num\">High risk</th><th>CSV</th>")
              .Append("</tr></thead><tbody>");
            foreach (ScanSummary s in scans)
            {
                sb.Append(s.Risky > 0 || s.HighRisk > 0 ? "<tr class=\"risky\">" : "<tr>");
                sb.Append("<td>").Append(Time(s.ReceivedAt)).Append("</td>");
                sb.Append("<td>").Append(H(s.SystemName)).Append("</td>");
                sb.Append(Num(s.Total)).Append(Num(s.Alive, "up")).Append(Num(s.Risky, "risk")).Append(Num(s.HighRisk, "risk"));
                sb.Append("<td><a href=\"/reports/").Append(s.UploadId.ToString(CultureInfo.InvariantCulture)).Append("\">download</a></td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table></div>");
        }

        if (scans.Count > 0)
        {
            ScanSummary latest = scans[0];
            sb.Append("<h2>Hosts in latest scan <span class=\"muted\">(").Append(Time(latest.ReceivedAt)).Append(")</span></h2>");
            if (hosts.Count == 0)
            {
                sb.Append("<div class=\"empty\">No host rows.</div>");
            }
            else
            {
                sb.Append("<div class=\"wrap\"><table><thead><tr><th>IP</th><th>Alive</th><th>Name</th><th>Model</th><th>OS</th><th>MAC</th><th>Vendor</th><th>Ports</th><th>Service</th>")
                  .Append("<th class=\"num\">Risk</th><th>Prohibited</th></tr></thead><tbody>");
                foreach (HostRow h in hosts)
                {
                    sb.Append(h.HasProhibited ? "<tr class=\"risky\">" : "<tr>");
                    sb.Append("<td>").Append(H(h.Ip)).Append("</td>");
                    sb.Append(h.Alive ? "<td class=\"up\">up</td>" : "<td class=\"muted\">down</td>");
                    sb.Append("<td>").Append(H(h.Name)).Append("</td>");
                    sb.Append("<td>").Append(H(h.Model)).Append("</td>");
                    sb.Append("<td>").Append(H(h.Os)).Append("</td>");
                    sb.Append("<td>").Append(H(h.Mac)).Append("</td>");
                    sb.Append("<td>").Append(H(h.Vendor)).Append("</td>");
                    sb.Append("<td>").Append(H(h.Ports)).Append("</td>");
                    sb.Append("<td>").Append(H(Clip(h.Service, 60))).Append("</td>");
                    sb.Append(Num(h.RiskScore, h.RiskScore >= ScanCsvParser.HighRiskThreshold ? "risk" : null));
                    sb.Append(h.HasProhibited ? "<td class=\"risk\">yes</td>" : "<td class=\"muted\">no</td>");
                    sb.Append("</tr>");
                }
                sb.Append("</tbody></table></div>");
            }
        }
        return Layout(site, sb.ToString(), who);
    }

    public static string Login(string? error)
    {
        var sb = new StringBuilder();
        sb.Append("<form class=\"login\" method=\"post\" action=\"/login\">");
        sb.Append("<label for=\"token\">Collector token</label>");
        if (error != null) sb.Append("<div class=\"err\">").Append(H(error)).Append("</div>");
        sb.Append("<input id=\"token\" name=\"token\" type=\"password\" autocomplete=\"current-password\" autofocus>");
        sb.Append("<button type=\"submit\">Sign in</button>");
        sb.Append("</form>");
        return Layout("Sign in", sb.ToString(), null);
    }

    public static string Forbidden(string site, Principal who) =>
        Layout("Forbidden", "<h1>Forbidden</h1><p>Your token is not allowed to view site <b>" + H(site) + "</b>.</p><p><a href=\"/\">Back to sites</a></p>", who);

    private const string Dash = "<span class=\"muted\">&mdash;</span>";

    // 배너 같은 긴 값은 표가 옆으로 끝없이 늘어나지 않도록 자른다.
    private static string Clip(string s, int max) => s.Length <= max ? s : s.Substring(0, max - 1) + "…";

    private static string Num(int? v, string? cls = null)
    {
        if (v is not int n) return "<td class=\"num\">" + Dash + "</td>";
        string css = cls != null && n > 0 ? "num " + cls : "num";
        return "<td class=\"" + css + "\">" + n.ToString(CultureInfo.InvariantCulture) + "</td>";
    }

    // 저장 형식 yyyy-MM-ddTHH:mm:ssZ → 사람이 읽는 형태.
    private static string Time(string? iso)
    {
        if (string.IsNullOrEmpty(iso)) return Dash;
        return H(iso.Replace('T', ' ').TrimEnd('Z')) + " <span class=\"muted\">UTC</span>";
    }

    private static string Layout(string title, string body, Principal? who)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>").Append(H(title)).Append(" · KetworkScanner Collector</title>");
        sb.Append("<style>").Append(Css).Append("</style></head><body>");
        sb.Append("<header><div><a href=\"/\">KetworkScanner Collector</a> <span class=\"sub\">central report collector</span></div>");
        if (who != null)
        {
            sb.Append("<div class=\"sub\">").Append(who.IsAdmin ? "admin" : H(who.Site))
              .Append(" &nbsp; <form method=\"post\" action=\"/logout\" style=\"display:inline\"><button type=\"submit\">Sign out</button></form></div>");
        }
        sb.Append("</header><main>").Append(body).Append("</main></body></html>");
        return sb.ToString();
    }
}
