using System;
using System.Collections.Generic;
using KetworkScanner.Discovery;

namespace KetworkScanner.Capture
{
    // 수동 캡처(PassiveListener)가 패킷 한 개에서 얻어낸 호스트 관찰 결과.
    // Ip는 아직 모를 수 있다(DHCP DISCOVER 등) — 그때는 Mac만으로 저장했다가 엔진이 나중에 MAC으로 합친다.
    // Source는 "pcap-arp", "pcap-dhcp", "pcap-mdns", "pcap-ssdp", "pcap-netbios", "pcap-tcp" 중 하나.
    public sealed record HostObservation(string Ip, string Mac, string Source, IReadOnlyList<Fact> Facts, DateTimeOffset At)
    {
        public bool HasIp => !string.IsNullOrEmpty(Ip);
        public bool HasMac => !string.IsNullOrEmpty(Mac);

        public override string ToString() => $"{Source} ip={Ip} mac={Mac} facts=[{string.Join(", ", Facts)}]";
    }
}
