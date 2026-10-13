using KetworkScanner;
using KetworkScanner.Upload;

namespace KetworkScanner.Cli;

// CLI 인자로부터 스캔 설정을 제공하는 IScanConfigProvider 구현.
// GUI의 설정 화면 대신 명령행 옵션이 설정 소스가 된다. FTP 업로드는 CLI에서 사용하지 않는다.
internal sealed class CliConfig : IScanConfigProvider
{
    public required ScanRangeList Ranges { get; init; }
    public required string PortList { get; init; }      // "22/80/443" 형식
    public required bool UsePorts { get; init; }
    public required string SystemName { get; init; }
    public required List<RefPortInfo> Reserved { get; init; }
    public required List<RefPortInfo> Prohibited { get; init; }

    public string GetPortList() => PortList;
    public UploadSettings Upload { get; init; } = new UploadSettings();
    public UploadSettings GetUploadSettings() => Upload;
    public string GetSystemName() => SystemName;
    public bool? GetUsePortChecking() => UsePorts;
    public List<RefPortInfo> GetReservedPortList() => Reserved;
    public List<RefPortInfo> GetProhibitPortList() => Prohibited;
    public ScanRangeList GetScanRanges() => Ranges;
}
