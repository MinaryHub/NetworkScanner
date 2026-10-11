using System.Globalization;

namespace NetworkScanner.Collector;

public sealed record ParsedHost(string Ip, bool Alive, string Name, string Mac, string Vendor, string Ports, int RiskScore, bool HasProhibited);

public sealed record ParsedScan(int Total, int Alive, int Risky, int HighRisk, IReadOnlyList<ParsedHost> Hosts);

// ScanEngine.BuildCsv가 만든 CSV를 헤더 이름 기준으로 읽는다(열 순서가 바뀌어도 동작).
public static class ScanCsvParser
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
                risk, prohibited));
        }
        return new ParsedScan(hosts.Count, alive, risky, high, hosts);
    }

    // 파일 이름의 첫 '_' 앞 부분이 시스템 이름(예: Office-PC_20261011_120000.csv → Office-PC).
    public static string SystemNameFromFileName(string fileName)
    {
        string stem = Path.GetFileNameWithoutExtension(fileName);
        int idx = stem.IndexOf('_');
        return idx > 0 ? stem.Substring(0, idx) : stem;
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
