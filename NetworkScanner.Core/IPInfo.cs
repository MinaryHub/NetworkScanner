using System.Collections.ObjectModel;
using System.Linq;

namespace NetworkScanner
{
    // 스캔 결과 행의 컬렉션. 엔진이 ItemsSyncRoot 락 아래에서만 수정하고, UI는 스냅샷을 떠서 표시한다.
    public class IPInfoList : ObservableCollection<IPInfo>
    {
        public void AddItem(IPInfo newitem)
        {
            if (!IsExist(newitem.Ip))
            {
                Add(newitem);
            }
        }

        public IPInfo? GetItem(string ip) => Items.FirstOrDefault(x => x.Ip == ip);

        public void DelItem(string ip)
        {
            IPInfo? item = GetItem(ip);
            if (item != null) Remove(item);
        }

        public bool IsExist(string ip) => GetItem(ip) != null;
    }

    // 호스트 한 대의 스캔 결과. INotifyPropertyChanged를 구현하지 않으므로 값 변경은 ItemsRefreshNeeded로 UI에 알린다.
    public class IPInfo
    {
        public string Ip { get; set; } = "";
        public string Ports { get; set; } = "";
        public string SystemName { get; set; } = "";
        public string RountTime { get; set; } = "";
        public bool Alive { get; set; }
        public string CommitDate { get; set; } = "";
        public string Description { get; set; } = "";
        public string Macaddr { get; set; } = "";
        public string Vendor { get; set; } = "";

        // 스캔 시 열린 포트 중 위험(백도어) 포트 목록과 일치하는 것이 있으면 true.
        public bool HasProhibitedPort { get; set; }

        // UI가 상태를 색상/배지로 표시할 때 쓰는 3단계 상태 키. Alive/HasProhibitedPort 조합으로 계산된다.
        public string StatusKey => !Alive ? "bad" : (HasProhibitedPort || RiskScore >= 40 ? "warn" : "good");
        public string StatusText => !Alive ? Localization.T("status.down") : (HasProhibitedPort ? Localization.T("status.warn") : Localization.T("status.up"));

        // 제조사·열린 포트로 추정한 장비 종류(참고용). UI의 "종류" 컬럼에 표시된다.
        public string DeviceType => string.IsNullOrEmpty(DeviceHint) ? DeviceClassifier.Classify(Vendor, Ports) : DeviceHint;
        public string DeviceHint { get; set; } = "";

        // Ping 응답의 TTL(0이면 미측정). OsGuess는 TTL로 추정한 OS 계열(참고용).
        public int Ttl { get; set; }
        public string OsGuess => OsGuesser.Guess(Ttl, Vendor, Ports, SystemName, OsHint);
        public string OsHint { get; set; } = "";

        // 열린 포트에서 수집한 서비스/배너 정보(예: "HTTP: nginx", "SSH-2.0-OpenSSH_8.9").
        public string Service { get; set; } = "";

        // SNMP sysDescr 등 식별 프로브가 준 장비 설명(없으면 ""). 이름의 출처는 IdentitySource("dns"/"netbios"/"mdns"/"snmp").
        public string SysDescr { get; set; } = "";
        public string IdentitySource { get; set; } = "";

        // 취약점/약한 설정 평가 결과(0~100)와 발견 항목 JSON. 평가를 끄면 0/"".
        public int RiskScore { get; set; }
        public string FindingsJson { get; set; } = "";

        // 자산 승인 여부(인벤토리 기준). 미승인 상태로 살아있으면 UI가 별도 표시한다.
        public bool Approved { get; set; }
        public string Owner { get; set; } = "";
    }
}
