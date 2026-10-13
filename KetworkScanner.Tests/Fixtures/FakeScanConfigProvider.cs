using System.Collections.Generic;
using KetworkScanner;
using KetworkScanner.Upload;

namespace KetworkScanner.Tests.Fixtures
{
    public class FakeScanConfigProvider : IScanConfigProvider
    {
        public ScanRangeList ScanRanges { get; set; } = new ScanRangeList();
        public List<RefPortInfo> ReservedPortList { get; set; } = new List<RefPortInfo>();
        public List<RefPortInfo> ProhibitPortList { get; set; } = new List<RefPortInfo>();

        public string PortList { get; set; } = "";
        public bool UsePortChecking { get; set; }

        public string GetPortList() => PortList;
        public UploadSettings Upload { get; set; } = new UploadSettings();
        public UploadSettings GetUploadSettings() => Upload;
        public string GetSystemName() => "TestSystem";
        public bool? GetUsePortChecking() => UsePortChecking;
        public List<RefPortInfo> GetReservedPortList() => ReservedPortList;
        public List<RefPortInfo> GetProhibitPortList() => ProhibitPortList;
        public ScanRangeList GetScanRanges() => ScanRanges;
    }
}
