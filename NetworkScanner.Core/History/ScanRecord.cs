using System;
using System.Collections.Generic;

namespace NetworkScanner.History
{
    // 한 번의 스캔에서 기록된 호스트 한 대의 결과. 문자열 컬럼은 null 대신 ""로 저장한다.
    public sealed record ScanHostRecord(
        string Ip, bool Alive, string Mac, string Vendor, string Name,
        string Ports, string Service, string Rtt, int Ttl, bool HasProhibited);

    // 한 번의 스캔 전체(시작/종료 시각, 시스템 이름, 예약 스캔 여부, 호스트 목록).
    public sealed record ScanRecord(
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt, string SystemName,
        bool Scheduled, IReadOnlyList<ScanHostRecord> Hosts)
    {
        // 엔진의 IPInfo 목록을 저장용 레코드로 변환한다. 스캔 종료 직후 호출하는 용도.
        public static ScanRecord FromItems(IEnumerable<IPInfo> items, DateTimeOffset started,
                                           DateTimeOffset finished, string systemName, bool scheduled)
        {
            var hosts = new List<ScanHostRecord>();
            foreach (IPInfo item in items)
            {
                if (string.IsNullOrEmpty(item.Ip)) continue;
                hosts.Add(new ScanHostRecord(
                    item.Ip,
                    item.Alive,
                    item.Macaddr ?? "",
                    item.Vendor ?? "",
                    item.SystemName ?? "",
                    item.Ports ?? "",
                    item.Service ?? "",
                    item.RountTime ?? "",
                    item.Ttl,
                    item.HasProhibitedPort));
            }
            return new ScanRecord(started, finished, systemName ?? "", scheduled, hosts);
        }
    }

    // scans 테이블의 한 행(목록 표시용 요약).
    public sealed record ScanSummary(
        long Id, DateTimeOffset StartedAt, DateTimeOffset FinishedAt, string SystemName,
        int Total, int Alive, int Prohibited, bool Scheduled);

    // hosts 테이블의 한 행: IP별로 누적된 인벤토리(처음/마지막 발견, 마지막 상태, 발견 횟수).
    public sealed record HostInventoryEntry(
        string Ip, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, DateTimeOffset? LastAliveAt,
        string LastMac, string LastVendor, string LastName, string LastPorts, bool LastAlive, int SeenCount);

    // 특정 IP가 스캔마다 어떤 상태였는지(시간순 이력).
    public sealed record HostHistoryEntry(
        long ScanId, DateTimeOffset StartedAt, bool Alive, string Mac, string Ports,
        string Service, bool HasProhibited);
}
