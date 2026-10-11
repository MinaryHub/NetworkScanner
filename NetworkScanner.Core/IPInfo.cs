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
        public string StatusKey => !Alive ? "bad" : (HasProhibitedPort ? "warn" : "good");
        public string StatusText => !Alive ? Localization.T("status.down") : (HasProhibitedPort ? Localization.T("status.warn") : Localization.T("status.up"));

        // 제조사·열린 포트로 추정한 장비 종류(참고용). UI의 "종류" 컬럼에 표시된다.
        public string DeviceType => DeviceClassifier.Classify(Vendor, Ports);

        // Ping 응답의 TTL(0이면 미측정). OsGuess는 TTL로 추정한 OS 계열(참고용).
        public int Ttl { get; set; }
        public string OsGuess => OsGuesser.FromTtl(Ttl);

        // 열린 포트에서 수집한 서비스/배너 정보(예: "HTTP: nginx", "SSH-2.0-OpenSSH_8.9").
        public string Service { get; set; } = "";
    }
}
