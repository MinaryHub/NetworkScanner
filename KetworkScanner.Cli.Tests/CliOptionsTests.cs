using KetworkScanner;
using KetworkScanner.Cli;

namespace KetworkScanner.Cli.Tests;

// 명령행 파서: 대역 형식, 옵션 값 검증, 하위 명령 검증, 프로필/동시성 우선순위.
public sealed class CliOptionsTests
{
    private static CliOptions Ok(params string[] args)
    {
        CliOptions o = CliOptions.Parse(args);
        Assert.Null(o.Error);
        return o;
    }

    private static string Fails(params string[] args)
    {
        CliOptions o = CliOptions.Parse(args);
        Assert.NotNull(o.Error);
        return o.Error!;
    }

    // ---- --range ----

    [Fact]
    public void Range_Cidr_IsExpandedToStartAndEnd()
    {
        // /24 는 네트워크/브로드캐스트 주소를 뺀 호스트 범위로 풀린다(IPRangeUtil.TryParseCidr).
        CliOptions o = Ok("--range", "192.168.1.0/24", "--ports", "22");
        ScanRangeInfo r = Assert.Single(o.Ranges);
        Assert.Equal("192.168.1.1", r.StartIP);
        Assert.Equal("192.168.1.254", r.EndIP);
    }

    [Fact]
    public void Range_StartEnd_And_SingleIp_AreAccepted()
    {
        CliOptions o = Ok("--range", "10.0.0.1-10.0.0.50", "--range", "10.0.1.7");
        Assert.Equal(2, o.Ranges.Count);
        Assert.Equal("10.0.0.1", o.Ranges[0].StartIP);
        Assert.Equal("10.0.0.50", o.Ranges[0].EndIP);
        Assert.Equal("10.0.1.7", o.Ranges[1].StartIP);
        Assert.Equal("10.0.1.7", o.Ranges[1].EndIP);
    }

    [Fact]
    public void Range_StartEnd_TrimsWhitespace()
    {
        CliOptions o = Ok("--range", " 10.0.0.1 - 10.0.0.9 ");
        Assert.Equal("10.0.0.1", o.Ranges[0].StartIP);
        Assert.Equal("10.0.0.9", o.Ranges[0].EndIP);
    }

    [Theory]
    [InlineData("fe80::1")]                 // IPv6 단일
    [InlineData("2001:db8::/64")]           // IPv6 CIDR
    [InlineData("fe80::1-fe80::ff")]        // IPv6 범위
    [InlineData("10.0.0.50-10.0.0.1")]      // 시작 > 끝
    [InlineData("10.0.0.300")]              // 잘못된 옥텟
    [InlineData("10.0.0.0/33")]             // 잘못된 프리픽스
    [InlineData("hello")]
    public void Range_RejectsIpv6_Reversed_AndGarbage(string value)
    {
        string err = Fails("--range", value);
        Assert.Contains("invalid --range", err);
    }

    [Fact]
    public void Range_WithoutValue_Fails()
    {
        Assert.Contains("--range requires", Fails("--range"));
    }

    [Fact]
    public void TryParseRange_RejectsStartGreaterThanEnd_AcrossOctets()
    {
        Assert.False(CliOptions.TryParseRange("10.0.1.0-10.0.0.255", out _));
        Assert.True(CliOptions.TryParseRange("10.0.0.255-10.0.1.0", out ScanRangeInfo r));
        Assert.Equal("10.0.0.255", r.StartIP);
        Assert.Equal("10.0.1.0", r.EndIP);
    }

    // ---- 스캔 옵션 ----

    [Fact]
    public void Ports_AcceptCommaOrSlash_AndNormalizeToSlashes()
    {
        CliOptions o = Ok("--ports", "22,80/443 8080");
        Assert.True(o.PortsSet);
        Assert.Equal("22/80/443/8080", o.Ports);
    }

    [Fact]
    public void Output_Formats_AreParsed_AndUnknownRejected()
    {
        Assert.Equal(OutputFormat.Json, Ok("-o", "json").Output);
        Assert.Equal(OutputFormat.Csv, Ok("--output", "CSV").Output);
        Assert.Equal(OutputFormat.Pdf, Ok("-o", "pdf", "--out", "x.pdf").Output);
        Assert.Contains("invalid --output", Fails("-o", "xml"));
        Assert.Contains("--out requires", Fails("--out"));
    }

    [Fact]
    public void SystemName_WithoutValue_Fails()
    {
        Assert.Contains("--system-name requires", Fails("--system-name"));
        Assert.Equal("Office PC", Ok("--system-name", "Office PC").SystemName);
    }

    [Fact]
    public void UploadAndNotify_ImplyUseSettings()
    {
        CliOptions o = Ok("--upload");
        Assert.True(o.Upload);
        Assert.True(o.UseSettings);
        Assert.False(o.Scheduled);
        CliOptions n = Ok("--notify", "--scheduled", "-q", "--no-history", "--no-discovery");
        Assert.True(n.Notify && n.UseSettings && n.Scheduled && n.Quiet && n.NoHistory && n.NoDiscovery);
    }

    [Fact]
    public void Lang_Parallelism_Limit_AreValidated()
    {
        Assert.Equal("ko", Ok("--lang", "KO").Language);
        Assert.True(Ok("--lang", "ko").LanguageSet);
        Assert.Contains("--lang", Fails("--lang", "fr"));
        Assert.Equal(8, Ok("--parallelism", "8").Parallelism);
        Assert.Contains("--parallelism", Fails("--parallelism", "0"));
        Assert.Contains("--parallelism", Fails("--parallelism", "513"));
        Assert.Equal(7, Ok("history", "--limit", "7").HistoryLimit);
        Assert.Contains("--limit", Fails("history", "--limit", "-1"));
    }

    [Fact]
    public void Allow_ParsesValidEntries_AndRejectsInvalid()
    {
        CliOptions o = Ok("--allow", "3389", "--allow", "10.0.0.5:22");
        Assert.Equal(2, o.Allow.Count);
        Assert.Contains("invalid --allow", Fails("--allow", "not-a-port"));
        Assert.Contains("--allow requires", Fails("--allow"));
    }

    [Fact]
    public void Profile_IsLowercased_AndUnknownRejected()
    {
        Assert.Equal("quick", Ok("--profile", "Quick").Profile);
        Assert.Contains("--profile", Fails("--profile", "insane"));
    }

    [Fact]
    public void UnknownOption_Fails_AndHelpWins()
    {
        Assert.Contains("unknown option", Fails("--bogus"));
        Assert.True(Ok("--range", "10.0.0.1", "--help").ShowHelp);
    }

    // ---- 하위 명령 ----

    [Fact]
    public void History_Subcommands_AreValidated()
    {
        CliOptions host = Ok("history", "host", "10.0.0.1", "-o", "json");
        Assert.Equal(CliCommand.History, host.Command);
        Assert.Equal("host", host.HistorySub);
        Assert.Equal("10.0.0.1", host.HistoryArg);
        Assert.Equal("scans", Ok("history").HistorySub);
        Assert.Equal("30", Ok("history", "prune", "30").HistoryArg);
        Assert.Contains("unknown history subcommand", Fails("history", "bogus"));
    }

    [Fact]
    public void Assets_Subcommands_AreValidated()
    {
        CliOptions set = Ok("assets", "set", "10.0.0.1", "--owner", "Kim", "--tags", "printer,3F", "--note", "");
        Assert.Equal(CliCommand.Assets, set.Command);
        Assert.Equal("set", set.Sub);
        Assert.Equal("10.0.0.1", Assert.Single(set.Args));
        Assert.Equal("Kim", set.Owner);
        Assert.Equal("printer,3F", set.Tags);
        Assert.Equal("", set.Note);

        CliOptions del = Ok("assets", "delete", "10.0.0.1", "10.0.0.2", "-y");
        Assert.Equal("delete", del.Sub);
        Assert.Equal(2, del.Args.Count);
        Assert.True(del.Yes);

        Assert.Equal("", Ok("assets").Sub);
        Assert.True(Ok("assets", "approve", "--all").All);
        Assert.Contains("unknown assets subcommand", Fails("assets", "bogus"));
        Assert.Contains("--owner requires", Fails("assets", "set", "10.0.0.1", "--owner"));
        Assert.Contains("--note requires", Fails("assets", "set", "10.0.0.1", "--note"));
    }

    [Fact]
    public void Alerts_Subcommands_AreValidated()
    {
        CliOptions snooze = Ok("alerts", "snooze", "5", "12", "--note", "patching");
        Assert.Equal(CliCommand.Alerts, snooze.Command);
        Assert.Equal("snooze", snooze.Sub);
        Assert.Equal(new[] { "5", "12" }, snooze.Args);
        Assert.Equal("patching", snooze.Note);
        Assert.True(Ok("alerts", "list", "--all").All);
        Assert.Contains("unknown alerts subcommand", Fails("alerts", "bogus"));
    }

    [Fact]
    public void Update_AcceptsOnlyCheckApplyOrNothing()
    {
        Assert.Equal("", Ok("update").Sub);
        Assert.Equal("check", Ok("update", "check", "--beta").Sub);
        Assert.True(Ok("update", "apply", "-y").Yes);
        Assert.Contains("unknown update subcommand", Fails("update", "now"));
    }

    [Fact]
    public void Settings_AcceptsExportImport_DiagTakesPath()
    {
        CliOptions e = Ok("settings", "export", "/tmp/x.json");
        Assert.Equal("export", e.Sub);
        Assert.Equal("/tmp/x.json", Assert.Single(e.Args));
        Assert.Contains("unknown settings subcommand", Fails("settings", "reset"));
        Assert.Equal("bundle.zip", Ok("diag", "bundle.zip").Sub);
    }

    // ---- 프로필과 명시적 옵션의 우선순위 ----

    [Fact]
    public void Profile_IsAppliedBeforeExplicitParallelism()
    {
        ScanOptions quick = CliScanOptions.Build(Ok("--profile", "quick"), null);
        Assert.Equal(ScanProfileKind.Quick, quick.Profile);
        Assert.Equal(128, quick.Parallelism);          // 프로필이 올린 값
        Assert.False(quick.BannerGrab);
        Assert.False(quick.IdentityProbes);
        Assert.False(quick.AssessVulnerabilities);
        Assert.False(quick.DeepDiscovery);

        // 인자 순서와 무관하게 --parallelism 이 프로필을 이긴다.
        Assert.Equal(8, CliScanOptions.Build(Ok("--profile", "quick", "--parallelism", "8"), null).Parallelism);
        Assert.Equal(8, CliScanOptions.Build(Ok("--parallelism", "8", "--profile", "quick"), null).Parallelism);

        ScanOptions thorough = CliScanOptions.Build(Ok("--profile", "thorough"), null);
        Assert.Equal(ScanProfileKind.Thorough, thorough.Profile);
        Assert.Equal(32, thorough.Parallelism);
        Assert.NotEmpty(thorough.ExtraPorts);
    }

    [Fact]
    public void Build_WithoutProfile_KeepsDefaults_AndAppliesAllowAndNoDiscovery()
    {
        ScanOptions o = CliScanOptions.Build(Ok("--allow", "3389", "--no-discovery"), null);
        Assert.Equal(ScanProfileKind.Standard, o.Profile);
        Assert.Equal(new ScanOptions().Parallelism, o.Parallelism);
        Assert.Contains("3389", o.RiskAllowList);
        Assert.False(o.DeepDiscovery);
    }

    [Fact]
    public void Build_FromSettings_ProfileOverridesSavedProfile()
    {
        var saved = new AppSettingsData { ScanParallelism = 16, ScanProfile = "thorough" };
        ScanOptions o = CliScanOptions.Build(Ok("--profile", "quick"), saved);
        Assert.Equal(ScanProfileKind.Quick, o.Profile);
        Assert.False(o.BannerGrab);
        Assert.Equal(128, o.Parallelism);

        ScanOptions kept = CliScanOptions.Build(Ok(), saved);
        Assert.Equal(ScanProfileKind.Thorough, kept.Profile);
        Assert.Equal(16, kept.Parallelism);
    }
}
