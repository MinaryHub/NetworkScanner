using System.Collections.Generic;
using KetworkScanner.Upload;

namespace KetworkScanner
{
    // 엔진이 스캔에 필요한 설정값(포트 목록, 업로드 설정, 시스템명 등)을 얻기 위해 의존하는 추상화.
    // 엔진이 UI 컨트롤을 직접 읽지 않게 하여 GUI/CLI/서비스/테스트가 각자 구현을 끼울 수 있다.
    public interface IScanConfigProvider
    {
        string GetPortList();
        UploadSettings GetUploadSettings();
        string GetSystemName();
        bool? GetUsePortChecking();
        List<RefPortInfo> GetReservedPortList();
        List<RefPortInfo> GetProhibitPortList();
        ScanRangeList GetScanRanges();
    }
}
