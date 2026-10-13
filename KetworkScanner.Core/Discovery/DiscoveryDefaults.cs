using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using KetworkScanner.Discovery.Fingerprint;
using KetworkScanner.Discovery.Infrastructure;
using KetworkScanner.Discovery.Multicast;

namespace KetworkScanner.Discovery
{
    // 설정(DiscoverySettings)으로 호스트별 프로브와 네트워크 전체 발견 목록을 만든다. 앱/CLI/서비스가 공통으로 쓴다.
    public static class DiscoveryDefaults
    {
        public static IReadOnlyList<IFactProbe> BuildFactProbes(DiscoverySettings d)
        {
            var probes = new List<IFactProbe>();
            if (d.Smb) probes.Add(new SmbProbe());
            if (d.Ssh) probes.Add(new SshProbe());
            if (d.Http) probes.Add(new HttpProbe());
            if (d.UdpProbes)
            {
                probes.Add(new DnsProbe());
                probes.Add(new NtpProbe());
                probes.Add(new SsdpUnicastProbe());
                probes.Add(new TftpProbe());
                probes.Add(new SipProbe());
            }
            return probes;
        }

        // 능동 ARP(ITargetedNetworkDiscovery)는 대상 목록을 엔진이 스캔마다 넘기므로 여기서는 지원 여부만 본다.
        public static IReadOnlyList<INetworkDiscovery> BuildNetworkDiscoveries(DiscoverySettings d, string snmpCommunity)
        {
            var list = new List<INetworkDiscovery>();
            if (d.Ssdp) list.Add(new SsdpDiscovery());
            if (d.MdnsBrowse) list.Add(new MdnsBrowser());
            if (d.NeighborTables) list.Add(new NeighborDiscovery());

            var agents = FactFusion.ParseSnmpAgents(d.SnmpAgents, snmpCommunity);
            if (d.GatewaySnmp)
            {
                foreach (IPAddress gw in DefaultGateways())
                    if (!agents.Any(a => a.Ip.Equals(gw))) agents.Add((gw, snmpCommunity));
            }
            if (agents.Count > 0) list.Add(new SnmpInfrastructureDiscovery(agents));

            if (d.ActiveArp && ActiveArpProber.IsSupported) list.Add(new ActiveArpDiscovery());
            return list;
        }

        // 활성 인터페이스들의 IPv4 기본 게이트웨이.
        public static IReadOnlyList<IPAddress> DefaultGateways()
        {
            var result = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (GatewayIPAddressInformation g in nic.GetIPProperties().GatewayAddresses)
                    {
                        IPAddress a = g.Address;
                        if (a.AddressFamily != AddressFamily.InterNetwork || IPAddress.Any.Equals(a) || result.Contains(a)) continue;
                        result.Add(a);
                    }
                }
            }
            catch { }
            return result;
        }
    }
}
