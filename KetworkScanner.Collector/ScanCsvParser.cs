using System.Globalization;
using System.Text.RegularExpressions;

namespace KetworkScanner.Collector;

public sealed record ParsedHost(
    string Ip, bool Alive, string Name, string Mac, string Vendor, string Ports, int RiskScore, bool HasProhibited,
    string OsHint = "", string OsVersion = "", string Model = "", string DeviceHint = "", string Service = "",
    string SwitchPort = "", string Ipv6 = "", bool Approved = false, string Owner = "");

public sealed record ParsedScan(int Total, int Alive, int Risky, int HighRisk, IReadOnlyList<ParsedHost> Hosts);

// ScanEngine.BuildCsv가 만든 CSV를 헤더 이름 기준으로 읽는다(열 순서가 바뀌어도 동작).
public static partial class ScanCsvParser
{
    public const int HighRiskThreshold = 40;

    // 스캐너 형식이 아니면(IPAddress/Alive 열이 없으면) null.
    public static ParsedScan? Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (text.Length > 0 && text[0] == '﻿') text = text.Substring(1);

        List<string[]> rows = CsvCodec.Parse(text);
        if (rows.Count == 0) return null;

        var col = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        string[] header = rows[0];
        for (int i = 0; i < header.Length; i++)
        {
            string name = header[i].Trim();
            if (name.Length > 0 && !col.ContainsKey(name)) col[name] = i;
        }
        if (!col.ContainsKey("IPAddress") || !col.ContainsKey("Alive")) return null;

        var hosts = new List<ParsedHost>(rows.Count - 1);
        int alive = 0, risky = 0, high = 0;
        for (int r = 1; r < rows.Count; r++)
        {
            string[] row = rows[r];
            string ip = Field(row, col, "IPAddress");
            if (ip.Length == 0) continue;

            bool isAlive = ParseBool(Field(row, col, "Alive"));
            bool prohibited = ParseBool(Field(row, col, "HasProhibitedPort"));
            int risk = ParseInt(Field(row, col, "RiskScore"));

            if (isAlive) alive++;
            if (prohibited) risky++;
            if (risk >= HighRiskThreshold) high++;

            hosts.Add(new ParsedHost(
                ip, isAlive,
                Field(row, col, "SystemName"),
                Field(row, col, "MacAddress"),
                Field(row, col, "Vendor"),
                Field(row, col, "Port"),
                risk, prohibited,
                OsHint: Field(row, col, "OsHint"),
                OsVersion: Field(row, col, "OsVersion"),
                Model: Field(row, col, "Model"),
                DeviceHint: Field(row, col, "DeviceHint"),
                Service: Field(row, col, "Service"),
                SwitchPort: Field(row, col, "SwitchPort"),
                Ipv6: Field(row, col, "Ipv6"),
                Approved: ParseBool(Field(row, col, "Approved")),
                Owner: Field(row, col, "Owner")));
        }
        return new ParsedScan(hosts.Count, alive, risky, high, hosts);
    }

    // 스캐너의 파일 이름 규칙(ScanEngine): <system>_yyyyMMdd_HHmmss[_(SCHEDULING)].csv, <system>_yyyyMMdd_HHmmss_report.html/.pdf.
    // 수집 서버는 같은 이름이 있으면 -2, -3… 을 덧붙인다. 시스템 이름 자체에 '_'가 있을 수 있으므로 오른쪽부터 떼어 낸다.
    [GeneratedRegex(@"^(?<name>.+?)_\d{8}_\d{6}(?:_\(SCHEDULING\))?(?:_report)?(?:-\d+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex FileNamePattern();

    public static string SystemNameFromFileName(string fileName)
    {
        string stem = Path.GetFileNameWithoutExtension(fileName);
        Match m = FileNamePattern().Match(stem);
        return m.Success ? m.Groups["name"].Value : stem;
    }

    private static string Field(string[] row, Dictionary<string, int> col, string name)
    {
        if (!col.TryGetValue(name, out int i) || i >= row.Length) return "";
        return CsvCodec.Unguard(row[i]).Trim();
    }

    private static bool ParseBool(string s) =>
        s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1" || s.Equals("yes", StringComparison.OrdinalIgnoreCase);

    private static int ParseInt(string s) =>
        int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : 0;
}
