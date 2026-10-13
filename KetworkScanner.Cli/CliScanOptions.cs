using KetworkScanner;

namespace KetworkScanner.Cli;

// 명령행 옵션과 settings.json으로부터 엔진 옵션을 만든다.
// 우선순위: 설정 파일 → --profile → 명시적 옵션(--parallelism, --allow, --no-discovery). 명시한 값이 항상 이긴다.
internal static class CliScanOptions
{
    public static ScanOptions Build(CliOptions o, AppSettingsData? saved)
    {
        ScanOptions options = saved != null ? ScanOptions.FromSettings(saved) : new ScanOptions();

        if (o.Profile != null)
        {
            ScanProfileKind kind = ScanProfiles.Parse(o.Profile);
            ScanProfiles.Apply(options, kind);
            options.Profile = kind;
        }

        // --parallelism은 프로필이 정한 동시성보다 우선한다.
        if (o.Parallelism > 0) options.Parallelism = o.Parallelism;
        options.RiskAllowList.AddRange(o.Allow);
        if (o.NoDiscovery) options.DeepDiscovery = false;
        return options;
    }
}
