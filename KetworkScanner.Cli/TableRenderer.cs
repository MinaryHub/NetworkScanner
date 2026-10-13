using System.Text;
using KetworkScanner;

namespace KetworkScanner.Cli;

// 스캔 결과를 터미널에서 읽기 좋은 정렬된 표로 렌더링한다. 살아있는 호스트를 IP 순으로 보여준다.
internal static class TableRenderer
{
    public static string Render(IReadOnlyList<IPInfo> items)
    {
        var alive = items.Where(i => i.Alive)
                         .OrderBy(i => SortKey(i.Ip))
                         .ToList();

        var headers = new[] { "IP", "STATUS", "NAME", "TYPE", "MODEL", "OS", "PORTS", "SERVICE", "MAC", "VENDOR", "RISK", "RTT" };
        // OS 열은 상세 버전(SMB/SSH 등으로 확인된 경우)을 우선 보여준다.
        var rows = alive.Select(i => new[]
        {
            i.Ip ?? "", i.StatusText ?? "", i.SystemName ?? "", Truncate(i.DeviceType, 22), Truncate(i.Model, 22), Truncate(string.IsNullOrEmpty(i.OsVersion) ? i.OsGuess : i.OsVersion, 26),
            i.Ports ?? "", Truncate(i.Service, 28), i.Macaddr ?? "", Truncate(i.Vendor, 22),
            i.RiskScore > 0 ? i.RiskScore.ToString() : "", i.RountTime ?? ""
        }).ToList();

        // 각 열 너비 = 헤더/값 중 최대 길이(과도하게 길어지지 않도록 상한도 둔다).
        int cols = headers.Length;
        var width = new int[cols];
        for (int c = 0; c < cols; c++)
        {
            width[c] = headers[c].Length;
            foreach (var row in rows) width[c] = Math.Max(width[c], row[c].Length);
        }

        var sb = new StringBuilder();
        AppendRow(sb, headers, width);
        sb.AppendLine(string.Join("-+-", width.Select(w => new string('-', w))));
        foreach (var row in rows) AppendRow(sb, row, width);

        int total = items.Count;
        int aliveCount = alive.Count;
        int prohibited = items.Count(i => i.HasProhibitedPort);
        sb.AppendLine();
        sb.Append($"alive: {aliveCount}   scanned: {total}");
        if (prohibited > 0) sb.Append($"   risky-port hosts: {prohibited}");
        int highRisk = items.Count(i => i.Alive && i.RiskScore >= IPInfo.WarnRiskScore);
        if (highRisk > 0) sb.Append($"   high-risk hosts: {highRisk}");

        return sb.ToString();
    }

    private static void AppendRow(StringBuilder sb, IReadOnlyList<string> cells, int[] width)
    {
        var padded = new string[cells.Count];
        for (int c = 0; c < cells.Count; c++) padded[c] = cells[c].PadRight(width[c]);
        sb.AppendLine(string.Join(" | ", padded).TrimEnd());
    }

    private static string Truncate(string? s, int max)
    {
        s ??= "";
        return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
    }

    // IP를 숫자 기준으로 정렬하기 위한 키(문자열 정렬이면 10이 2보다 앞서는 문제를 피한다).
    private static uint SortKey(string ip)
    {
        return System.Net.IPAddress.TryParse(ip, out var addr) ? IPRangeUtil.ToUInt32(addr) : 0;
    }
}
