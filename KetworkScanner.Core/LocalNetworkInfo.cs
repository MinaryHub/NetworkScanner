using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace KetworkScanner
{
    // 설치된 PC가 속한 로컬 서브넷을 감지해, 최초 실행 시 기본 스캔 대역으로 제안한다.
    public static class LocalNetworkInfo
    {
        public static ScanRangeInfo? GetLocalSubnetRange()
        {
            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

            foreach (NetworkInterface nic in candidates)
            {
                foreach (UnicastIPAddressInformation addr in nic.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(addr.Address)) continue;
                    if (addr.IPv4Mask == null) continue;

                    uint ip = IPRangeUtil.ToUInt32(addr.Address);
                    uint mask = IPRangeUtil.ToUInt32(addr.IPv4Mask);
                    if (mask == 0 || mask == 0xFFFFFFFF) continue; // 마스크 없음/호스트 전용 인터페이스는 제외

                    uint network = ip & mask;
                    uint broadcast = network | ~mask;
                    uint start = network + 1;
                    uint end = broadcast - 1;
                    if (end < start) continue; // /31, /32처럼 스캔할 호스트가 없는 대역은 제외

                    return new ScanRangeInfo
                    {
                        Index = 0,
                        StartIP = IPRangeUtil.FromUInt32(start).ToString(),
                        EndIP = IPRangeUtil.FromUInt32(end).ToString(),
                        Description = string.Format(Localization.T("local.autodetected"), nic.Name),
                    };
                }
            }

            return null;
        }
    }
}
