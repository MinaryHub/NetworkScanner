using KetworkScanner;
using KetworkScanner.Cli;

namespace KetworkScanner.Cli.Tests;

// 터미널 표: 열 구성, 살아있는 호스트만, 숫자 기준 IP 정렬, 요약 줄.
public sealed class TableRendererTests
{
    private static IPInfo Host(string ip, bool alive = true, Action<IPInfo>? init = null)
    {
        var h = new IPInfo { Ip = ip, Alive = alive };
        init?.Invoke(h);
        return h;
    }

    [Fact]
    public void Render_HasExpectedColumns_InOrder()
    {
        string table = TableRenderer.Render(new[] { Host("10.0.0.1", init: h => { h.SystemName = "gw"; h.Ports = "22/80"; }) });
        string header = table.Split('\n')[0];
        string[] columns = header.Split('|').Select(c => c.Trim()).ToArray();
        Assert.Equal(new[] { "IP", "STATUS", "NAME", "TYPE", "MODEL", "OS", "PORTS", "SERVICE", "MAC", "VENDOR", "RISK", "RTT" }, columns);
        // 두 번째 줄은 헤더 구분선
        Assert.StartsWith("---", table.Split('\n')[1]);
    }

    [Fact]
    public void Render_ShowsOnlyAliveHosts_SortedNumerically()
    {
        var items = new[]
        {
            Host("10.0.0.10"),
            Host("10.0.0.2"),
            Host("10.0.0.9", alive: false),
            Host("10.0.0.1"),
        };
        string table = TableRenderer.Render(items);
        string[] lines = table.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        string[] body = lines.Skip(2).Where(l => l.StartsWith("10.", StringComparison.Ordinal)).ToArray();
        Assert.Equal(3, body.Length);
        Assert.StartsWith("10.0.0.1 ", body[0]);
        Assert.StartsWith("10.0.0.2 ", body[1]);
        Assert.StartsWith("10.0.0.10", body[2]);
        Assert.DoesNotContain("10.0.0.9", table);
        Assert.Contains("alive: 3   scanned: 4", table);
    }

    [Fact]
    public void Render_PutsValuesUnderTheirColumns_AndCountsRiskyHosts()
    {
        var items = new[]
        {
            Host("10.0.0.7", init: h =>
            {
                h.SystemName = "pc7";
                h.Model = "OptiPlex";
                h.OsVersion = "Windows 11 22631";
                h.Ports = "445/31337";
                h.Service = "smb";
                h.Macaddr = "AA-BB-CC-DD-EE-FF";
                h.Vendor = "Dell";
                h.RiskScore = 65;
                h.RountTime = "3";
                h.HasProhibitedPort = true;
            }),
        };
        string table = TableRenderer.Render(items);
        string[] lines = table.Split('\n');
        string[] header = lines[0].Split('|').Select(c => c.Trim()).ToArray();
        string[] row = lines[2].Split('|').Select(c => c.Trim()).ToArray();
        Assert.Equal(header.Length, row.Length);

        string Cell(string column) => row[Array.IndexOf(header, column)];
        Assert.Equal("10.0.0.7", Cell("IP"));
        Assert.Equal("pc7", Cell("NAME"));
        Assert.Equal("OptiPlex", Cell("MODEL"));
        Assert.Equal("Windows 11 22631", Cell("OS"));      // OsVersion이 TTL 추정보다 우선
        Assert.Equal("445/31337", Cell("PORTS"));
        Assert.Equal("smb", Cell("SERVICE"));
        Assert.Equal("AA-BB-CC-DD-EE-FF", Cell("MAC"));
        Assert.Equal("Dell", Cell("VENDOR"));
        Assert.Equal("65", Cell("RISK"));
        Assert.Equal("3", Cell("RTT"));

        Assert.Contains("risky-port hosts: 1", table);
        Assert.Contains("high-risk hosts: 1", table);
    }

    [Fact]
    public void Render_TruncatesLongValues_WithEllipsis()
    {
        string longService = new string('s', 60);
        string table = TableRenderer.Render(new[] { Host("10.0.0.1", init: h => h.Service = longService) });
        Assert.DoesNotContain(longService, table);
        Assert.Contains("…", table);
    }

    [Fact]
    public void Render_EmptyList_StillPrintsHeaderAndSummary()
    {
        string table = TableRenderer.Render(Array.Empty<IPInfo>());
        Assert.Contains("IP", table);
        Assert.Contains("alive: 0   scanned: 0", table);
    }
}
