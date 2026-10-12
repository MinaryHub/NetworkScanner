using NetworkScanner;
using NetworkScanner.Service;

// 헤드리스 스케줄러. GUI 없이 settings.json의 예약 시간/연속 모니터링 설정대로 스캔을 돌리고,
// 결과 저장·업로드·알림·이력 기록을 수행한다. Windows 서비스, systemd, launchd, 포그라운드 모두 같은 바이너리다.
//   netscan-service                 포그라운드 실행(Ctrl+C로 종료)
//   netscan-service --run-once      예약과 무관하게 지금 한 번 스캔하고 종료(cron/launchd 간격 실행용)

// "--apply-update <stage> <install> <pid> [service]": Windows 업데이트 도우미 모드(부모 종료 후 파일 교체).
if (args.Length > 0 && args[0] == "--apply-update")
{
    return NetworkScanner.Updates.HeadlessUpdater.RunApplyHelper(args[1..]);
}

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "NetworkScanner");
builder.Services.AddSystemd();
builder.Services.AddSingleton(new SchedulerOptions { RunOnce = args.Contains("--run-once") });
builder.Services.AddHostedService<ScanSchedulerWorker>();
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

IHost host = builder.Build();
await host.RunAsync();
return Environment.ExitCode;
