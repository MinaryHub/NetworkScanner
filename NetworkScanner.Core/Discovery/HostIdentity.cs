using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkScanner.Discovery
{
    // 식별 프로브 한 번의 결과. Source는 프로브 이름(NetBIOS/mDNS/SNMP), 나머지는 알아낸 범위 안에서만 채운다.
    // Attributes에는 프로브별 원시 값을 "netbios.name", "snmp.sysdescr"처럼 접두사를 붙여 담는다.
    public sealed record HostIdentity(
        string Source,
        string? Name,
        string? Description,
        string? OsHint,
        string? DeviceHint,
        IReadOnlyDictionary<string, string> Attributes)
    {
        public const string SourceNetBios = "NetBIOS";
        public const string SourceMdns = "mDNS";
        public const string SourceSnmp = "SNMP";

        // 병합/이름 선택 규칙이 참조하는 잘 알려진 속성 키.
        public const string AttrNetBiosName = "netbios.name";
        public const string AttrNetBiosWorkgroup = "workgroup";
        public const string AttrNetBiosMac = "mac";
        public const string AttrMdnsName = "mdns.name";
        public const string AttrSnmpSysName = "snmp.sysname";
        public const string AttrSnmpSysDescr = "snmp.sysdescr";
    }

    // 호스트 한 대를 대상으로 단일 프로토콜 질의를 보내 식별 정보를 얻는다. 구현체는 절대 예외를 던지지 않고
    // 실패/무응답/취소 시 null을 돌려준다.
    public interface IIdentityProbe
    {
        string Name { get; }
        Task<HostIdentity?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct);
    }
}
